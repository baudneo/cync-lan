import base64
import datetime
import json
import logging
import os
import random
import signal
import string
from pathlib import Path
from typing import Optional

import aiohttp
import yaml
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cync_lan.const import (
    CYNC_ACCOUNT_LANGUAGE,
    CYNC_ACCOUNT_PASSWORD,
    CYNC_ACCOUNT_USERNAME,
    CYNC_API_BASE,
    CYNC_CLOUD_AUTH_PATH,
    CYNC_CONFIG_DIR,
    CYNC_CONFIG_FILE_PATH,
    CYNC_CORP_ID,
    CYNC_EXPORT_SOURCE,
    CYNC_LOG_NAME,
    CYNC_OVERWRITE_CONFIG_FILE,
    CYNC_SECRET_KEY,
)
from cync_lan.structs import ComputedTokenStruct, EntityState, GlobalObject

logger = logging.getLogger(CYNC_LOG_NAME)
g = GlobalObject()


class CyncCloudAPI:
    api_timeout: int = 8
    lp: str = "CyncCloudAPI"
    auth_cache_file = CYNC_CLOUD_AUTH_PATH
    token_cache: ComputedTokenStruct
    http_session: aiohttp.ClientSession = None
    _instance: "CyncCloudAPI" = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, **kwargs):
        self.api_timeout = kwargs.get("api_timeout", 8)
        self.lp = kwargs.get("lp", self.lp)

    async def close(self):
        """
        Close the aiohttp session if it exists and is not closed.
        """
        lp = f"{self.lp}:close:"
        if self.http_session and not self.http_session.closed:
            logger.debug(f"{lp} Closing aiohttp ClientSession")
            await self.http_session.close()
            self.http_session = None

    async def _check_session(self):
        """
        Check if the aiohttp session is initialized.
        If not, create a new session.
        """
        if not self.http_session or self.http_session.closed:
            logger.debug(
                f"{self.lp}:_check_session: Creating new aiohttp ClientSession"
            )
            self.http_session = aiohttp.ClientSession()
            await self.http_session.__aenter__()

    async def read_token_cache(self) -> Optional[ComputedTokenStruct]:
        """
        Read the encrypted token cache from a file.
        Returns:
            CloudTokenData: The cached token data if available, otherwise None.
        """
        lp = f"{self.lp}:read_token_cache:"
        try:
            with open(self.auth_cache_file, "rb") as f:
                encrypted_data = f.read()
            cipher = self._get_fernet_cipher()
            decrypted_json = cipher.decrypt(encrypted_data)
            token_dict = json.loads(decrypted_json.decode("utf-8"))
            logger.debug(f"{lp} Cached token data read and decrypted successfully")
            return ComputedTokenStruct(**token_dict)
        except FileNotFoundError:
            logger.debug(f"{lp} Token cache file not found: {self.auth_cache_file}")
            return None
        except Exception as e:
            logger.error(
                f"{lp} Failed to decrypt or parse token cache. It may be corrupt or the secret key changed: {e}"
            )
            return None

    async def check_token(self) -> bool:
        """Check if we need to request a new OTP code for 2FA authentication."""
        lp = f"{self.lp}:check_tkn:"
        self.token_cache = await self.read_token_cache()
        if not self.token_cache:
            logger.debug(f"{lp} No cached token found, requesting OTP...")
            return False
        if self.token_cache.expires_at < datetime.datetime.now(datetime.UTC):
            # try refreshing first
            succ = await self.refresh_access_token()
            if not succ:
                logger.debug(f"{lp} Token expired, requesting OTP...")
            return succ

        else:
            logger.debug(f"{lp} Token is valid, using cached token")
        return True

    async def request_otp(self) -> bool:
        """
        Request an OTP code for 2FA authentication.
        """
        lp = f"{self.lp}:request_otp:"
        await self._check_session()
        req_otp_url = f"{CYNC_API_BASE}two_factor/email/verifycode"
        if CYNC_EXPORT_SOURCE is None:
            if not CYNC_ACCOUNT_USERNAME or not CYNC_ACCOUNT_PASSWORD:
                logger.error(
                    f"{lp} Cync account username or password not set, cannot request OTP!"
                )
                return False
            auth_data = {
                "corp_id": CYNC_CORP_ID,
                "email": CYNC_ACCOUNT_USERNAME,
                "local_lang": CYNC_ACCOUNT_LANGUAGE,
            }
            sesh = self.http_session
            try:
                otp_r = await sesh.post(
                    req_otp_url,
                    json=auth_data,
                    timeout=aiohttp.ClientTimeout(total=self.api_timeout),
                )
                otp_r.raise_for_status()
            except aiohttp.ClientResponseError as e:
                logger.error(f"{lp} Failed to request OTP code: {e}")
                return False
        return True

    async def refresh_access_token(self) -> bool:
        lp = f"{self.lp}:refresh token:"
        return await self._send_tkn_post(
            f"{CYNC_API_BASE}user/token/refresh",
            {"refresh_token": self.token_cache.refresh_token},
        )

    async def send_otp(self, otp_code: int) -> bool:
        lp = f"{self.lp}:send_otp:"
        await self._check_session()
        if not otp_code:
            logger.error("OTP code must be provided")
            return False
        elif not isinstance(otp_code, int):
            try:
                otp_code = int(otp_code)
            except ValueError:
                logger.error(f"{lp} OTP code must be an integer, got {type(otp_code)}")
                return False

        api_auth_url = f"{CYNC_API_BASE}user_auth/two_factor"
        auth_data = {
            "corp_id": CYNC_CORP_ID,
            "email": CYNC_ACCOUNT_USERNAME,
            "password": CYNC_ACCOUNT_PASSWORD,
            "two_factor": otp_code,
            "resource": "".join(random.choices(string.ascii_lowercase, k=16)),
        }
        logger.debug(
            f"{lp} Sending OTP code: {otp_code} to Cync Cloud API for authentication"
        )
        return await self._send_tkn_post(api_auth_url, auth_data)

    async def _send_tkn_post(self, url, data):
        try:
            self.http_session: aiohttp.ClientSession
            resp = await self.http_session.post(
                url, json=data, timeout=aiohttp.ClientTimeout(total=self.api_timeout)
            )
            resp.raise_for_status()
            iat = datetime.datetime.now(datetime.UTC)
            token_data = await resp.json()
        except aiohttp.ClientResponseError as e:
            logger.error(f"Failed to authenticate: {e}")
            return False
        except json.JSONDecodeError as je:
            logger.error(f"Failed to decode JSON: {je}")
            return False
        except KeyError as ke:
            logger.error(f"Failed to get key from JSON: {ke}")
            return False
        except Exception:
            logger.warning(f"{lp} Failed to refresh credentials")
            return False
        else:
            # add issued_at to the token data for computing the expiration datetime
            token_data["issued_at"] = iat
            return await self.write_token_cache(ComputedTokenStruct(**token_data))

    async def write_token_cache(self, tkn: ComputedTokenStruct) -> bool:
        """
        Write the encrypted token cache to file.
        Args:
            tkn (ComputedTokenStruct): The token data to write to the cache.
        Returns:
            bool: True if the write was successful, False otherwise.
        """
        lp = f"{self.lp}:write_token_cache:"
        try:
            json_data = tkn.model_dump_json().encode("utf-8")
            cipher = self._get_fernet_cipher()
            encrypted_data = cipher.encrypt(json_data)
            with open(self.auth_cache_file, "wb") as f:
                f.write(encrypted_data)
            os.chmod(self.auth_cache_file, 0o777)
            logger.debug(
                f"{lp} Token cache encrypted and written successfully to: {self.auth_cache_file}"
            )
            self.token_cache = tkn
            return True
        except Exception as e:
            logger.error(f"{lp} Failed to write encrypted token cache: {e}")
            return False

    async def request_device_data(self):
        """Get a list of Cync homes that have their own devices for a particular account."""
        lp = f"{self.lp}:get_devices:"
        await self._check_session()
        user_id = self.token_cache.user_id
        access_token = self.token_cache.access_token
        api_devices_url = f"{CYNC_API_BASE}user/{user_id}/subscribe/devices"
        headers = {"Access-Token": access_token}
        sesh = self.http_session
        try:
            r = await sesh.get(
                api_devices_url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.api_timeout),
            )
        except aiohttp.ClientResponseError as e:
            logger.error(f"{lp} Failed to get devices: {e}")
            raise e
        except json.JSONDecodeError as je:
            logger.error(f"{lp} Failed to decode JSON: {je}")
            raise je
        except KeyError as ke:
            logger.error(f"{lp} Failed to get key from JSON: {ke}")
            raise ke
        else:
            ret = await r.json()

        # {'error': {'msg': 'Access-Token Expired', 'code': 4031021}}
        if "error" in ret:
            error_data = ret["error"]
            if (
                "msg" in error_data
                and error_data["msg"]
                and error_data["msg"].lower() == "access-token expired"
            ):
                logger.error(f"{lp} Access-Token expired, you need to re-authenticate!")
                # logger.error(f"{lp} Access-Token expired, re-authenticating...")
                # return self.get_devices(*self.authenticate_2fa())
        return ret

    async def get_cync_home_properties(self, product_id: str, device_id: str):
        """
        Get properties for a Cync home. Properties contain a device list (bulbsArray),
        groups (groupsArray), and saved light effects (lightShows).
        """
        lp = f"{self.lp}:get_properties:"
        await self._check_session()
        access_token = self.token_cache.access_token
        api_device_prop_url = (
            f"{CYNC_API_BASE}product/{product_id}/device/{device_id}/property"
        )
        headers = {"Access-Token": access_token}
        sesh = self.http_session
        try:
            r = await sesh.get(
                api_device_prop_url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.api_timeout),
            )
            ret = await r.json()
        except aiohttp.ClientResponseError as e:
            logger.error(f"{lp} Failed to get device properties: {e}")
        except json.JSONDecodeError as je:
            logger.error(f"{lp} Failed to decode JSON: {je}")
            raise je
        except KeyError as ke:
            logger.error(f"{lp} Failed to get key from JSON: {ke}")
            raise ke

        # {'error': {'msg': 'Access-Token Expired', 'code': 4031021}}
        logit = False
        if "error" in ret:
            error_data = ret["error"]
            if "msg" in error_data and error_data["msg"]:
                if error_data["msg"].lower() == "access-token expired":
                    raise Exception(
                        f"{lp} Access-Token expired, you need to re-authenticate!"
                    )
                    # logger.error("Access-Token expired, re-authenticating...")
                    # return self.get_devices(*self.authenticate_2fa())
                else:
                    logit = True

                if "code" in error_data:
                    cync_err_code = error_data["code"]
                    if cync_err_code == 4041009:
                        # no properties for this home ID
                        # I've noticed lots of empty homes in the returned data,
                        # we only parse homes with an assigned name and a 'bulbsArray'
                        logit = False
                    else:
                        logger.debug(
                            f"{lp} DBG>>> error code != 4041009 (int) ---> {type(cync_err_code) = } -- {cync_err_code =} /// setting logit = True"
                        )
                        logit = True
                else:
                    logger.debug(
                        f"{lp} DBG>>> no 'code' in error data, setting logit = True"
                    )
                    logit = True
            if logit is True:
                logger.warning(f"{lp} Cync Cloud API Error: {error_data}")
        return ret

    async def export_config_file(self) -> bool:
        """Get Cync devices from the cloud"""
        if CYNC_EXPORT_SOURCE is not None:
            logger.warning(
                f"{self.lp} The source for export has been configured as a file: {CYNC_EXPORT_SOURCE} "
                f"skipping cloud export and using the provided file instead..."
            )
            src_file = Path(CYNC_EXPORT_SOURCE)
            if not src_file.exists():
                logger.error(
                    f"{self.lp} The provided export source file does not exist: {CYNC_EXPORT_SOURCE}"
                )
                return False
            elif not src_file.is_file():
                logger.error(
                    f"{self.lp} The provided export source path is not a file: {CYNC_EXPORT_SOURCE}"
                )
                return False
            else:
                try:
                    with src_file.open("r") as f:
                        exported_data = yaml.safe_load(f)
                except Exception as file_exc:
                    logger.error(
                        f"{self.lp} Failed to read export source file: {CYNC_EXPORT_SOURCE} -> {file_exc}"
                    )
                    return False
                else:
                    logger.debug(
                        f"{self.lp} Successfully read export source file: {CYNC_EXPORT_SOURCE}"
                    )
        else:
            # use the cloud
            exported_data = await self.request_device_data()
        cync_lan_cfg = await self._parse_raw_export(exported_data)
        # write config to file in YAML format
        base_cfg_path = Path(CYNC_CONFIG_FILE_PATH)
        raw_cfg_file_out = base_cfg_path
        if CYNC_OVERWRITE_CONFIG_FILE is False:
            counter = 1
            while raw_cfg_file_out.exists():
                raw_cfg_file_out = base_cfg_path.with_name(
                    f"{base_cfg_path.stem}_{counter}{base_cfg_path.suffix}"
                )
                counter += 1
        try:
            with raw_cfg_file_out.open("w") as f:
                f.write(yaml.dump(cync_lan_cfg))
            os.chmod(raw_cfg_file_out, 0o777)
        except Exception as file_exc:
            logger.error(
                f"{self.lp} Failed to write cync-lan config to file: {CYNC_CONFIG_FILE_PATH} -> {file_exc}"
            )
            return False
        else:
            return True

    async def _parse_raw_export(self, exported_home_data: dict):
        """Take exported cloud data and format it into a working config dict to be dumped in YAML format."""
        lp = f"{self.lp}:parse export:"
        new_cfg = {}
        # What we get from the Cync cloud API
        base_file_path = Path(CYNC_CONFIG_DIR) / "raw_mesh.cync"
        raw_file_out = base_file_path
        # strip out empty configs (IDK why, I have a bunch with access_code 77777 that are empty)
        for raw_home in exported_home_data:
            if "name" not in raw_home or len(raw_home["name"]) < 1:
                logger.debug(
                    f"{lp} No name found for Cync home (safely ignore), skipping..."
                )
                # I see several empty 'home' configs in the returned data, they don't have a name,
                # any properties/devices, so we can safely ignore them
                continue
            if "properties" not in raw_home:
                # only pull device list for valid Cync homes
                raw_home["properties"] = await self.get_cync_home_properties(
                    raw_home["product_id"], raw_home["id"]
                )
            if "bulbsArray" not in raw_home["properties"]:
                logger.debug(
                    f"{lp} No 'bulbsArray' in Cync home: '{raw_home['name']}' properties (safely ignore), skipping..."
                )
                continue
            logger.debug(
                f"{lp} 'properties' and 'bulbsArray' found in exported config, proceeding..."
            )
            new_home: dict = {
                kv: raw_home[kv] for kv in ("access_key", "id", "mac") if kv in raw_home
            }
            new_cfg[raw_home["name"]] = new_home
            new_home["devices"] = {}
            entity_reg = {}
            for raw_device in raw_home["properties"]["bulbsArray"]:
                if any(
                    checkattr not in raw_device
                    for checkattr in (
                        "deviceID",
                        "displayName",
                        "mac",
                        "deviceType",
                        "wifiMac",
                        "firmwareVersion",
                    )
                ):
                    logger.warning(
                        f"{lp} Missing required attribute (deviceID, displayName, deviceType, MACs, firmwareVersion) in Cync device, skipping: {raw_device}"
                    )
                    continue
                new_device: dict = {}
                wifi_mac = str(raw_device["wifiMac"])
                bt_mac = str(raw_device["mac"])
                dev_name = str(raw_device["displayName"])
                dev_type = int(raw_device["deviceType"])
                fw_ver = str(raw_device["firmwareVersion"])
                # switchID ? maybe links them in their logic?
                raw_id = str(raw_device["deviceID"])
                home_id = raw_id[:9]
                raw_dev = raw_id.split(home_id)[1]
                dev_id = int(raw_dev[-3:])
                sub_id = 0
                parent = None
                # Seems the thermostat has a multi-endpoint deviceID but is a single entry
                # 169573386
                # 7 (multi endpoint is 3 digit, this is only 1)
                # 009
                # { "hvacSystem": { "changeoverMode": 0, "auxHeatStages": 1, "auxFurnaceType": 1, "stages": 1, "furnaceType": 1, "type": 2, "powerLines": 1 },
                # "thermostatSensors": [ { "pin": "025572", "name": "Living Room", "type": "savant" }, { "pin": "044604", "name": "Bedroom Sensor", "type": "savant" }, { "pin": "022724", "name": "Thermostat sensor 3", "type": "savant" } ] } ]
                hvac_cfg = None
                if "hvacSystem" in raw_device:
                    hvac_cfg = raw_device["hvacSystem"]
                    if "thermostatSensors" in raw_device:
                        hvac_cfg["thermostatSensors"] = raw_device["thermostatSensors"]
                    logger.debug(
                        f"{lp} Found HVAC device '{dev_name}' (ID: {dev_id}): {hvac_cfg}"
                    )
                    logger.info(
                        f"{lp} HVAC devices are currently unsupported, work is in progress to "
                        f"get the thermostat and temp sensors added"
                    )
                    continue
                    new_device["hvac"] = hvac_cfg
                if len(raw_dev) > 4:
                    # firmwareVersion = Unknown is also an identifier for sub-devices
                    # sub-device wifiMac will always be 01:02:03:04:05:06 even if parent has WiFi, BT MACs match
                    sub_id = int(raw_dev[:3])
                    if dev_id in entity_reg:
                        if sub_id in entity_reg[dev_id]:
                            logger.error(
                                f"{lp} Duplicate sub-device ID {sub_id} found for parent device ID {dev_id} in home "
                                f"'{raw_home['name']}' (device name: '{dev_name}'), Please open an issue with debug "
                                f"logs enabled..."
                            )
                            continue
                    logger.info(
                        f"{lp} Staging sub-device ({sub_id}) named: '{dev_name}' with parent device ID {dev_id} in "
                        f"home '{raw_home['name']}' devices registry"
                    )
                    state = EntityState(dev_id=dev_id, sub_id=sub_id, name=dev_name)
                    if dev_id in entity_reg:
                        entity_reg[dev_id][sub_id] = state.name
                    else:
                        entity_reg[dev_id] = {sub_id: state.name}
                    continue
                elif len(raw_dev) == 4:
                    logger.debug(
                        f"{lp} FOUND: '{dev_name}' has a thermostat related quirk with a value of: {raw_dev[3]}"
                    )
                # END OF SUB DEVICE PARSING

                # cync_device = CyncNode(
                #     name=dev_name,
                #     node_id=dev_id,
                #     dev_type=dev_type,
                #     mac=bt_mac,
                #     wifi_mac=wifi_mac,
                #     fw_version=fw_ver,
                #     hvac=hvac_cfg,
                # )
                new_device["name"] = dev_name
                new_device["type"] = dev_type
                # new_device["is_plug"] = cync_device.is_plug
                # new_device["supports_temperature"] = cync_device.supports_temperature
                # new_device["supports_rgb"] = cync_device.supports_rgb
                new_device["fw"] = fw_ver
                new_device["mac"] = bt_mac
                new_device["wifi_mac"] = wifi_mac
                # give it the default 0, if it has children, we will overwrite the 0
                new_device["endpoints"] = {0: dev_name}
                # del cync_device
                new_home["devices"][dev_id] = new_device

            # END OF DEVICE PARSING LOOP
            # check sub dev reg
            if entity_reg:
                for node_id, endpoint_data in entity_reg.items():
                    if node_id in new_home["devices"]:
                        # overwrite the default 0 endpoint with the children
                        new_home["devices"][node_id]["endpoints"] = endpoint_data

        # END OF HOME PARSING LOOP
        # write raw exported config to file for debugging, only if export source is None
        if CYNC_EXPORT_SOURCE is None:
            if CYNC_OVERWRITE_CONFIG_FILE is False:
                # basic numbered suffix logic to prevent overwriting existing files
                counter = 1
                while raw_file_out.exists():
                    raw_file_out = base_file_path.with_name(
                        f"{base_file_path.stem}_{counter}{base_file_path.suffix}"
                    )
                    counter += 1
            try:
                with open(raw_file_out, "w") as _f:
                    _f.write(yaml.dump(exported_home_data))
                os.chmod(raw_file_out, 0o777)
            except Exception as file_exc:
                logger.error(
                    f"{lp} Failed to write RAW config to '{raw_file_out}': {file_exc}"
                )
            else:
                logger.debug(f"{lp} Dumped RAW cloud export data to: {raw_file_out}")

        config_dict = {"exported_homes": new_cfg}
        return config_dict

    def _get_fernet_cipher(self) -> Fernet:
        """
        Derives a secure, 32-byte url-safe base64-encoded key from the CYNC_SECRET_KEY
        passphrase using PBKDF2 and initializes a fernet cipher suite.
        """
        if not CYNC_SECRET_KEY:
            logger.critical("CYNC_SECRET_KEY is not set! You must configure this!")
            signal.raise_signal(signal.SIGINT)
        else:
            passphrase = CYNC_SECRET_KEY.encode()
        # A static salt is used because the target file is local and we need to derive
        # the exact same key across restarts without storing it on disk.
        salt = b"cync_lan_static_salt_for_local_storage"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(passphrase))
        return Fernet(key)
