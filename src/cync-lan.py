#!/usr/bin/env python3
import ast
import asyncio
import datetime
import getpass
import json
import logging
import os
import random
import signal
import ssl
import struct
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from functools import partial
from json import JSONDecodeError
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Callable, Coroutine, Any

import amqtt
import amqtt.session
import requests
import uvloop
import yaml
from amqtt import client as amqtt_client
from amqtt.mqtt.constants import QOS_0, QOS_1

__version__: str = "0.0.5"

from requests import HTTPError

CYNC_VERSION: str = __version__
REPO_URL: str = "https://github.com/baudneo/cync-lan"
DEVICE_LWT_MSG: bytes = b"offline"

# This will run an async task every x seconds to check if any device is offline or online.
# Hopefully keeps devices in sync (seems to do pretty good).
CYNC_API_BASE: str = "https://api.gelighting.com/v2/"
CYNC_MESH_CHECK_INTERVAL: int = int(os.environ.get("CYNC_MESH_CHECK", 30)) or 30
CYNC_MQTT_URL = os.environ.get("CYNC_MQTT_URL", "mqtt://homeassistant.local:1883")
CYNC_CERT = os.environ.get("CYNC_CERT", "certs/cert.pem")
CYNC_KEY = os.environ.get("CYNC_KEY", "certs/key.pem")
CYNC_TOPIC = os.environ.get("CYNC_TOPIC", "cync_lan")
CYNC_HASS_TOPIC = os.environ.get("CYNC_HASS_TOPIC", "homeassistant")
CYNC_HASS_STATUS_TOPIC = os.environ.get("CYNC_HASS_STATUS_TOPIC", "status")
CYNC_HASS_BIRTH_MSG = os.environ.get("CYNC_HASS_BIRTH_MSG", "online")
CYNC_HASS_WILL_MSG = os.environ.get("CYNC_HASS_WILL_MSG", "offline")
CYNC_PORT = os.environ.get("CYNC_PORT", 23779)
CYNC_HOST = os.environ.get("CYNC_HOST", "0.0.0.0")
CYNC_CHUNK_SIZE = os.environ.get("CYNC_CHUNK_SIZE", 2048)
YES_ANSWER = ("true", "1", "yes", "y", "t", 1)
CYNC_RAW = os.environ.get("CYNC_RAW_DEBUG", "0").casefold() in YES_ANSWER
CYNC_DEBUG = os.environ.get("CYNC_DEBUG", "0").casefold() in YES_ANSWER
CORP_ID: str = "1007d2ad150c4000"
DATA_BOUNDARY = 0x7E
RAW_MSG = (
    " Set the CYNC_RAW_DEBUG env var to 1to see the data" if CYNC_RAW is False else ""
)
logger = logging.getLogger("cync-lan")
formatter = logging.Formatter(
    "%(asctime)s.%(msecs)d %(levelname)s [%(module)s:%(lineno)d] > %(message)s",
    "%m/%d/%y %H:%M:%S",
)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


@dataclass
class CacheData:
    all_data: bytes = b""
    timestamp: float = 0
    data: bytes = b""
    data_len: int = 0
    needed_len: int = 0


# from cync2mqtt
def random_login_resource():
    return "".join([chr(ord("a") + random.randint(0, 26)) for _ in range(0, 16)])


def bytes2list(byte_string: bytes) -> List[int]:
    """Convert a byte string to a list of integers"""
    # Interpret the byte string as a sequence of unsigned integers (little-endian)
    int_list = struct.unpack("<" + "B" * (len(byte_string)), byte_string)
    return list(int_list)


def hex2list(hex_string: str) -> List[int]:
    """Convert a hex string to a list of integers"""
    x = bytes().fromhex(hex_string)
    return bytes2list(x)


def ints2hex(ints: List[int]) -> str:
    """Convert a list of integers to a hex string"""
    return bytes(ints).hex(" ")


def ints2bytes(ints: List[int]) -> bytes:
    """Convert a list of integers to a byte string"""
    return bytes(ints)


def parse_unbound_firmware_version(
    data_struct: bytes, lp: str
) -> Optional[Tuple[str, int, str]]:
    """Parse the firmware version from binary hex data."""
    # LED controller sends this data after cync app connects via BTLE
    # 1f 00 00 00 fa 8e 14 00 50 22 33 08 00 ff ff ea 11 02 08 a1 [01 03 01 00 00 00 00 00 f8
    lp = f"{lp}firmware_version:"
    if data_struct[0] != 0x00:
        logger.error(
            f"{lp} Invalid first byte value: {data_struct[0]} should be 0x00 for firmware version data"
        )

    n_idx = 20  # Starting index for firmware information
    firmware_type = "device" if data_struct[n_idx + 2] == 0x01 else "network"
    n_idx += 3

    firmware_version = []
    try:
        while len(firmware_version) < 5 and data_struct[n_idx] != 0x00:
            firmware_version.append(int(chr(data_struct[n_idx])))
            n_idx += 1
        if not firmware_version:
            logger.warning(
                f"{lp} No firmware version found in packet: {data_struct.hex(' ')}"
            )
            return None
            # network firmware (this one is set to ascii 0 (0x30))
            # 00 00 00 00 00 fa 00 20 00 00 00 00 00 00 00 00
            # ea 00 00 00 86 01 00 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c1 7e

    except (IndexError, ValueError) as e:
        logger.error(f"{lp} Exception occurred while parsing firmware version: {e}")
        return None

    else:
        if firmware_type == "device":
            firmware_str = f"{firmware_version[0]}.{firmware_version[1]}.{''.join(map(str, firmware_version[2:]))}"
        else:
            firmware_str = "".join(map(str, firmware_version))
        firmware_version_int = int("".join(map(str, firmware_version)))
        logger.debug(
            f"{lp} {firmware_type} firmware VERSION: {firmware_version_int} ({firmware_str})"
        )

    return firmware_type, firmware_version_int, firmware_str


@dataclass
class MeshInfo:
    status: List[Optional[List[Optional[int]]]]
    id_from: int


class PhoneAppStructs:
    @dataclass
    class AppRequests:
        auth_header: Tuple[int] = (0x13, 0x00, 0x00, 0x00)
        connect_header: Tuple[int] = (0xA3, 0x00, 0x00, 0x00)

    @dataclass
    class AppResponses:
        auth_resp: Tuple[int] = (0x18, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00)
        # connect response needs toe xtract the queue id from the request

    requests: AppRequests = AppRequests()
    responses: AppResponses = AppResponses()
    headers = (0x13, 0xA3, 0x18)


class DeviceStructs:
    def __iter__(self):
        return iter([self.requests, self.responses])

    @dataclass
    class DeviceRequests:
        """These are packets devices send to the server"""

        x23: Tuple[int] = tuple([0x23])
        xc3: Tuple[int] = tuple([0xC3])
        xd3: Tuple[int] = tuple([0xD3])
        x83: Tuple[int] = tuple([0x83])
        x73: Tuple[int] = tuple([0x73])
        x7b: Tuple[int] = tuple([0x7B])
        x43: Tuple[int] = tuple([0x43])
        xa3: Tuple[int] = tuple([0xA3])
        xab: Tuple[int] = tuple([0xAB])
        headers: Tuple[int] = (0x23, 0xC3, 0xD3, 0x83, 0x73, 0x7B, 0x43, 0xA3, 0xAB)

        def __iter__(self):
            return iter(self.headers)

    @dataclass
    class DeviceResponses:
        """These are the packets the server sends to the device"""

        auth_ack: Tuple[int] = (0x28, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00)
        # todo: figure out correct bytes for this
        connection_ack: Tuple[int] = (
            0xC8,
            0x00,
            0x00,
            0x00,
            0x0B,
            0x0D,
            0x07,
            0xE8,
            0x03,
            0x0A,
            0x01,
            0x0C,
            0x04,
            0x1F,
            0xFE,
            0x0C,
        )
        x48_ack: Tuple[int] = (0x48, 0x00, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00)
        x88_ack: Tuple[int] = (0x88, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00)
        ping_ack: Tuple[int] = (0xD8, 0x00, 0x00, 0x00, 0x00)
        x78_base: Tuple[int] = (0x78, 0x00, 0x00, 0x00)
        x7b_base: Tuple[int] = (0x7B, 0x00, 0x00, 0x00, 0x07)

    requests: DeviceRequests = DeviceRequests()
    responses: DeviceResponses = DeviceResponses()
    headers: Tuple[int] = (0x23, 0xC3, 0xD3, 0x83, 0x73, 0x7B, 0x43, 0xA3, 0xAB)

    @staticmethod
    def xab_generate_ack(queue_id: bytes, msg_id: bytes):
        """
        Respond to a 0xAB packet from the device, needs queue_id and msg_id to reply with.
        Has ascii 'xlink_dev' in reply
        """
        _x = bytes([0xAB, 0x00, 0x00, 0x03])
        hex_str = (
            "78 6c 69 6e 6b 5f 64 65 76 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "e3 4f 02 10"
        )
        dlen = (
            len(queue_id) + len(msg_id) + len(bytes.fromhex(hex_str.replace(" ", "")))
        )
        _x += bytes([dlen])
        _x += queue_id
        _x += msg_id
        _x += bytes().fromhex(hex_str)
        return _x

    @staticmethod
    def x88_generate_ack(msg_id: bytes):
        """Respond to a 0x83 packet from the device, needs a msg_id to reply with"""
        _x = bytes([0x88, 0x00, 0x00, 0x00, 0x03])
        _x += msg_id
        return _x

    @staticmethod
    def x48_generate_ack(msg_id: bytes):
        """Respond to a 0x43 packet from the device, needs a queue and msg id to reply with"""
        # set last msg_id digit to 0
        msg_id = msg_id[:-1] + b"\x00"
        _x = bytes([0x48, 0x00, 0x00, 0x00, 0x03])
        _x += msg_id
        return _x

    @staticmethod
    def x7b_generate_ack(queue_id: bytes, msg_id: bytes):
        """
        Respond to a 0x73 packet from the device, needs a queue and msg id to reply with.
        This is also called for 0x83 packets AFTER seeing a 0x73 packet.
        Not sure of the intricacies yet, seems to be bound to certain queue ids.
        """
        _x = bytes([0x7B, 0x00, 0x00, 0x00, 0x07])
        _x += queue_id
        _x += msg_id
        return _x


@dataclass
class DeviceStatus:
    """
    A class that represents a Cync devices status.
    This may need to be changed as new devices are bought and added.
    """

    state: Optional[int] = None
    brightness: Optional[int] = None
    temperature: Optional[int] = None
    red: Optional[int] = None
    green: Optional[int] = None
    blue: Optional[int] = None


class GlobalState:
    # We need access to each object. Might as well centralize them.
    server: "CyncLanServer"
    cync_lan: "CyncLAN"
    mqtt: "MQTTClient"


@dataclass
class Tasks:
    receive: Optional[asyncio.Task] = None
    send: Optional[asyncio.Task] = None

    def __iter__(self):
        return iter([self.receive, self.send])


APP_HEADERS = PhoneAppStructs()
DEVICE_STRUCTS = DeviceStructs()
ALL_HEADERS = list(DEVICE_STRUCTS.headers) + list(APP_HEADERS.headers)


class MessageCallback:
    id: int
    original_message: Union[None, str, bytes, List[int]] = None
    sent_at: Optional[float] = None
    callback: Optional[Callable[..., Coroutine[Any, Any, None]]] = None

    args: List = []
    kwargs: Dict = {}

    def __str__(self):
        return f"MessageCallback ID: {self.id} sent at: {datetime.datetime.fromtimestamp(self.sent_at)}"

    def __eq__(self, other: int):
        return self.id == other

    def __hash__(self):
        return hash(self.id)

    def __init__(self, msg_id: int):
        self.id = msg_id
        self.lp = f"MessageCallback:{self.id}:"

    def __call__(self):
        if self.callback:
            logger.debug(f"{self.lp} Calling callback...")
            return self.callback(*self.args, **self.kwargs)
        else:
            logger.debug(f"{self.lp} No callback set, skipping...")
        return None


class Messages:
    x83: List[MessageCallback] = []
    x73: Dict[int, MessageCallback] = {}


class CyncCloudAPI:
    api_timeout: int = 5
    lp: str = "CyncCloudAPI"

    def __init__(self, **kwargs):
        self.api_timeout = kwargs.get("api_timeout", 5)

    # https://github.com/unixpickle/cbyge/blob/main/login.go
    def get_cloud_mesh_info(self):
        """Get Cync devices from the cloud, all cync devices are bt or bt/wifi.
        Meaning they will always have a BT mesh (as of March 2024)"""
        (auth, userid) = self.authenticate_2fa()
        _mesh_networks = self.get_devices(auth, userid)
        for _mesh in _mesh_networks:
            _mesh["properties"] = self.get_properties(
                auth, _mesh["product_id"], _mesh["id"]
            )
        return _mesh_networks

    def authenticate_2fa(
        self,
        uname: Optional[str] = None,
        password: Optional[str] = None,
        otp_code: Optional[str] = None,
    ):
        """
        Authenticate with the Cync Cloud API and get a token.

        Returns:
            Tuple[str, str]: Access token and user ID
        """
        lp = f"{self.lp}:authenticate_2fa:"
        if uname is None:
            if cli_email:
                uname = cli_email
                logger.debug(f"{lp} No email provided, using CLI arg: {uname}")
        else:
            logger.debug(f"{lp} Using email from kwargs: {uname}")
        # get user input if neither provided
        if not uname:
            uname = input("Enter Cync Account Username/Email:  ")

        if not otp_code:
            # Ask to be sent an email with OTP code
            api_otp_url = f"{CYNC_API_BASE}two_factor/email/verifycode"
            auth_data = {"corp_id": CORP_ID, "email": uname, "local_lang": "en-us"}
            otp_r = requests.post(api_otp_url, json=auth_data, timeout=self.api_timeout)
            try:
                otp_r.raise_for_status()
            except requests.exceptions.HTTPError as e:
                logger.error(f"Failed to get OTP code: {e}")
                raise e
            otp_code = input("Enter emailed OTP code (check junk/spam):  ")
        else:
            logger.debug(f"{lp} Using OTP code from CLI arg: {otp_code}")

        if not password:
            # no kwargs password, check cli
            if cli_password:
                password = cli_password
                logger.debug(f"{lp} No password provided, using CLI arg: {password}")
            # no kwarg or cli password, get from user
            else:
                password = getpass.getpass()
        api_auth_url = f"{CYNC_API_BASE}user_auth/two_factor"
        auth_data = {
            "corp_id": CORP_ID,
            "email": uname,
            "password": password,
            "two_factor": otp_code,
            "resource": random_login_resource(),
        }
        r = requests.post(api_auth_url, json=auth_data, timeout=self.api_timeout)
        try:
            r.raise_for_status()
            rjson = r.json()
        except requests.exceptions.HTTPError as e:
            logger.exception(f"Failed to authenticate: {e}")
            raise e
        except JSONDecodeError as je:
            logger.exception(f"Failed to decode JSON: {je}")
            raise je

        except KeyError as ke:
            logger.exception(f"Failed to get key from JSON: {ke}")
            raise ke
        else:
            logger.info(f"API Auth Response: {rjson}")
            return rjson["access_token"], rjson["user_id"]

    def get_devices(self, auth_token: str, user: str):
        """Get a list of devices for a particular user."""
        api_devices_url = f"{CYNC_API_BASE}user/{user}/subscribe/devices"
        headers = {"Access-Token": auth_token}
        r = requests.get(
            api_devices_url.format(user=user), headers=headers, timeout=self.api_timeout
        )
        ret = r.json()
        # {'error': {'msg': 'Access-Token Expired', 'code': 4031021}}
        if "error" in ret:
            error_data = ret["error"]
            if (
                "msg" in error_data
                and error_data["msg"]
                and error_data["msg"].lower() == "access-token expired"
            ):
                raise HTTPError("Access-Token expired, you need to re-authenticate.")
                # logger.error("Access-Token expired, re-authenticating...")
                # return self.get_devices(*self.authenticate_2fa())
        return ret

    def get_properties(self, auth_token: str, product_id: str, device_id: str):
        """Get properties for a single device. Properties contains device list (bulbsArray), groups (groupsArray), and saved light effects (lightShows)."""
        api_device_info_url = "https://api.gelighting.com/v2/product/{product_id}/device/{device_id}/property"
        headers = {"Access-Token": auth_token}
        r = requests.get(
            api_device_info_url.format(product_id=product_id, device_id=device_id),
            headers=headers,
            timeout=self.api_timeout,
        )
        ret = r.json()
        # {'error': {'msg': 'Access-Token Expired', 'code': 4031021}}
        logit = False
        if "error" in ret:
            error_data = ret["error"]
            if (
                "msg" in error_data
                and error_data["msg"]
            ):
                if error_data["msg"].lower() == "access-token expired":
                    raise HTTPError("Access-Token expired, you need to re-authenticate.")
                    # logger.error("Access-Token expired, re-authenticating...")
                    # return self.get_devices(*self.authenticate_2fa())
                else:
                    logit = True

                if 'code' in error_data:
                    cync_err_code = error_data['code']
                    if cync_err_code == 4041009:
                        # no properties for this home ID
                        # I've noticed lots of empty homes in the returned data,
                        # we only parse homes with an assigned name and a 'bulbsArray'
                        logit = False
                    else:
                        logger.debug(f"DBG>>> error code != 4041009 (int) ---> {type(cync_err_code) = } -- {cync_err_code =} /// setting logit = True")
                        logit = True
                else:
                    logger.debug(f"DBG>>> no 'code' in error data, setting logit = True")
                    logit = True
            if logit is True:
                logger.warning(f"Cync Cloud API Error: {error_data}")
        return ret

    @staticmethod
    def mesh_to_config(mesh_info):
        """Take exported cloud data and format it to write to file"""
        mesh_conf = {}

        try:
            with open("./raw_mesh.cync", "w") as _f:
                _f.write(yaml.dump(mesh_info))
        except Exception as file_exc:
            logger.error("Failed to write raw mesh info to file: %s" % file_exc)
        else:
            logger.debug("Dumped raw config from Cync account to file: ./raw_mesh.cync")
        for mesh_ in mesh_info:
            if "name" not in mesh_ or len(mesh_["name"]) < 1:
                logger.debug("No name found for mesh, skipping...")
                continue

            if "properties" not in mesh_ or "bulbsArray" not in mesh_["properties"]:
                logger.debug(
                    "No properties found for mesh OR no 'bulbsArray' in properties, skipping..."
                )
                continue
            new_mesh = {
                kv: mesh_[kv] for kv in ("access_key", "id", "mac") if kv in mesh_
            }
            mesh_conf[mesh_["name"]] = new_mesh

            logger.debug("properties and bulbsArray found for mesh, processing...")
            new_mesh["devices"] = {}
            for cfg_bulb in mesh_["properties"]["bulbsArray"]:
                if any(
                    checkattr not in cfg_bulb
                    for checkattr in (
                        "deviceID",
                        "displayName",
                        "mac",
                        "deviceType",
                        "wifiMac",
                    )
                ):
                    logger.warning(
                        "Missing required attribute in Cync bulb, skipping: %s"
                        % cfg_bulb
                    )
                    continue
                # last 3 digits of deviceID
                __id = int(str(cfg_bulb["deviceID"])[-3:])
                wifi_mac = cfg_bulb["wifiMac"]
                name = cfg_bulb["displayName"]
                _mac = cfg_bulb["mac"]
                _type = int(cfg_bulb["deviceType"])
                _fw_ver = cfg_bulb["firmwareVersion"]

                bulb_device = CyncDevice(
                    name=name,
                    cync_id=__id,
                    cync_type=_type,
                    mac=_mac,
                    wifi_mac=wifi_mac,
                    fw_version=_fw_ver,
                )
                new_bulb = {}
                for attr_set in (
                    "name",
                    # "is_plug",
                    # "supports_temperature",
                    # "supports_rgb",
                    "mac",
                    "wifi_mac",
                ):
                    value = getattr(bulb_device, attr_set)
                    if value:
                        new_bulb[attr_set] = value
                    else:
                        logger.warning("Attribute not found for bulb: %s" % attr_set)
                new_bulb["type"] = _type
                new_bulb["is_plug"] = bulb_device.is_plug
                new_bulb["supports_temperature"] = bulb_device.supports_temperature
                new_bulb["supports_rgb"] = bulb_device.supports_rgb
                new_bulb["fw"] = _fw_ver

                new_mesh["devices"][__id] = new_bulb

        config_dict = {"account data": mesh_conf}

        return config_dict


type_2_str = {
    31: "Full Color C by GE BTLE A19 Bulb",
    37: "Dimmer Switch with Motion and Ambient Light",
    68: "Indoor Direct Connect Plug",
    113: "Wire-Free White Temperature Dimmer Switch",
    133: "Full Color Direct Connect LED Light Strip Controller",
    137: "Full Color Direct Connect A19 Bulb",
    138: "Full Color Direct Connect BR30 Floodlight",
    140: "Full Color Direct Connect Outdoor PAR38 Floodlight",
    146: "Full Color Direct Connect Edison ST19 Bulb",
    147: "Full Color Direct Connect Edison G25 Bulb",
    148: "Dimmable Direct Connect Edison ST19 Bulb",
}


class CyncDevice:
    """
    A class to represent a Cync device imported from a config file. This class is used to manage the state of the device
    and send commands to it by using its device ID defined when the device was added to your Cync account.
    """

    lp = "CyncDevice:"
    id: int = None
    tasks: Tasks = Tasks()
    type: Optional[int] = None
    _supports_rgb: Optional[bool] = None
    _supports_temperature: Optional[bool] = None
    _is_plug: Optional[bool] = None
    _mac: Optional[str] = None
    wifi_mac: Optional[str] = None
    _online: bool = False
    DeviceTypes: Dict[str, List[int]] = {
        "BULB": [31, 137, 146, 148],
        "SWITCH": [113],
        "BATTERY": [113],
        "DIMMER": [113],
        "STRIP": [133],
        "PLUG": [64, 65, 66, 67, 68],
        "EDISON": [146, 148],
    }
    Capabilities = {
        "ONOFF": [
            1,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            13,
            14,
            15,
            17,
            18,
            19,
            20,
            21,
            22,
            23,
            24,
            25,
            26,
            27,
            28,
            29,
            30,
            31,  # BTLE only bulb?
            32,
            33,
            34,
            35,
            36,
            37,
            38,
            39,
            40,
            48,
            49,
            51,
            52,
            53,
            54,
            55,
            56,
            57,
            58,
            59,
            61,
            62,
            63,
            64,
            65,
            66,
            67,
            68,
            80,
            81,
            82,
            83,
            85,
            128,
            129,
            130,
            131,
            132,
            133,
            134,
            135,
            136,
            137,
            138,
            139,
            140,
            141,
            142,
            143,
            144,
            145,
            146,
            147,
            148,
            149,
            150,
            151,
            152,
            153,
            154,
            156,
            158,
            159,
            160,
            161,
            162,
            163,
            164,
            165,
        ],
        "BRIGHTNESS": [
            1,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            13,
            14,
            15,
            17,
            18,
            19,
            20,
            21,
            22,
            23,
            24,
            25,
            26,
            27,
            28,
            29,
            30,
            31,  # BTLE only bulb?
            32,
            33,
            34,
            35,
            36,
            37,
            48,
            49,
            55,
            56,
            80,
            81,
            82,
            83,
            85,
            128,
            129,
            130,
            131,
            132,
            133,
            134,
            135,
            136,
            137,
            138,
            139,
            140,
            141,
            142,
            143,
            144,
            145,
            146,
            147,
            148,
            149,
            150,
            151,
            152,
            153,
            154,
            156,
            158,
            159,
            160,
            161,
            162,
            163,
            164,
            165,
        ],
        "COLORTEMP": [
            5,
            6,
            7,
            8,
            10,
            11,
            14,
            15,
            19,
            20,
            21,
            22,
            23,
            25,
            26,
            28,
            29,
            30,
            31,
            32,
            33,
            34,
            35,
            80,
            82,
            83,
            85,
            129,
            130,
            131,
            132,
            133,
            135,
            136,
            137,
            138,
            139,
            140,
            141,
            142,
            143,
            144,
            145,
            146,
            147,
            153,
            154,
            156,
            158,
            159,
            160,
            161,
            162,
            163,
            164,
            165,
        ],
        "RGB": [
            6,
            7,
            8,
            21,
            22,
            23,
            30,
            31,  # BTLE only bulb?
            32,
            33,
            34,
            35,
            131,
            132,
            133,
            137,
            138,
            139,
            140,
            141,
            142,
            143,
            146,
            147,
            153,
            154,
            156,
            158,
            159,
            160,
            161,
            162,
            163,
            164,
            165,
        ],
        "MOTION": [37, 49, 54],
        "AMBIENT_LIGHT": [37, 49, 54],
        "WIFICONTROL": [
            36,
            37,
            38,
            39,
            40,
            48,
            49,
            51,
            52,
            53,
            54,
            55,
            56,
            57,
            58,
            59,
            61,
            62,
            63,
            64,
            65,
            66,
            67,
            68,
            80,
            81,
            128,
            129,
            130,
            131,
            132,
            133,
            134,
            135,
            136,
            137,
            138,
            139,
            140,
            141,
            142,
            143,
            144,
            145,
            146,
            147,
            148,
            149,
            150,
            151,
            152,
            153,
            154,
            156,
            158,
            159,
            160,
            161,
            162,
            163,
            164,
            165,
        ],
        "PLUG": [64, 65, 66, 67, 68],
        "SWITCH": [113, 37],
        "FAN": [81],
        "MULTIELEMENT": {"67": 2},
        "DYNAMIC": [],
        "MUSIC_SYNC": [],
    }

    def __init__(
        self,
        cync_id: int,
        cync_type: Optional[int] = None,
        name: Optional[str] = None,
        mac: Optional[str] = None,
        wifi_mac: Optional[str] = None,
        fw_version: Optional[str] = None,
        home_id: Optional[int] = None,
    ):
        self.control_bytes = bytes([0x00, 0x00])
        if cync_id is None:
            raise ValueError("ID must be provided to constructor")
        self.id = cync_id
        self.type = cync_type
        self.home_id: Optional[int] = home_id
        self.hass_id: str = f"{home_id}-{cync_id}"
        self._mac = mac
        self.wifi_mac = wifi_mac
        self._version: Optional[str] = None
        self.version = fw_version
        if name is None:
            name = f"device_{cync_id}"
        self.name = name
        self.lp = f"CyncDevice:{self.name}({cync_id}):"
        self._status: DeviceStatus = DeviceStatus()
        self._mesh_alive_byte: Union[int, str] = 0x00
        # state: 0:off 1:on
        self._state: int = 0
        # 0-100
        self._brightness: int = 0
        # 0-100 (warm to cool)
        self._temperature: int = 0
        # 0-255
        self._r: int = 0
        self._g: int = 0
        self._b: int = 0

    @property
    def version(self) -> Optional[str]:
        return self._version

    @version.setter
    def version(self, value: Union[str, int]) -> None:
        if value is None:
            return
        if isinstance(value, int):
            self._version = value
        elif isinstance(value, str):
            if value == '':
                # it is empty
                logger.debug(f"{self.lp} in CyncDevice.version(), the passed value is an empty string!")
            else:
                self._version = int(value.replace(".", "").strip())

    def check_dev_type(self, dev_type: int) -> dict:
        dev_types = {}
        for dtype in self.DeviceTypes:
            if dev_type in self.DeviceTypes[dtype]:
                dev_types[dtype] = True
            else:
                # dev_types[dtype] = False
                pass
        return dev_types

    def check_dev_capabilities(self, dev_type: int) -> Dict[str, bool]:
        """Check what capabilities a device type has."""
        dev_caps = {}
        for cap in self.Capabilities:
            if dev_type in self.Capabilities[cap]:
                dev_caps[cap] = True
            else:
                # dev_caps[cap] = False
                pass
        return dev_caps

    @property
    def mac(self) -> str:
        return str(self._mac) if self._mac is not None else None

    @mac.setter
    def mac(self, value: str) -> None:
        self._mac = str(value)

    @property
    def bt_only(self) -> bool:
        return self.type not in self.Capabilities["WIFICONTROL"]

    @property
    def has_wifi(self) -> bool:
        return self.type in self.Capabilities["WIFICONTROL"]

    @property
    def is_plug(self) -> bool:
        if self._is_plug is not None:
            return self._is_plug
        if self.type is None:
            return False
        return self.type in self.Capabilities["PLUG"]

    @is_plug.setter
    def is_plug(self, value: bool) -> None:
        self._is_plug = value

    @property
    def is_dimmable(self) -> bool:
        if self.type is None:
            return False
        return self.type in self.Capabilities["BRIGHTNESS"]

    @property
    def is_full_color(self) -> bool:
        if self.type is None:
            return False
        return all(
            {
                self.type in self.Capabilities["RGB"],
                self.type in self.Capabilities["COLORTEMP"],
            }
        )

    @property
    def supports_rgb(self) -> bool:
        if self._supports_rgb is not None:
            return self._supports_rgb
        if self._supports_rgb or self.type in self.Capabilities["RGB"]:
            return True

        return False

    @supports_rgb.setter
    def supports_rgb(self, value: bool) -> None:
        self._supports_rgb = value

    @property
    def supports_temperature(self) -> bool:
        if self._supports_temperature is not None:
            return self._supports_temperature
        if self.supports_rgb or self.type in self.Capabilities["COLORTEMP"]:
            return True
        return False

    @supports_temperature.setter
    def supports_temperature(self, value: bool) -> None:
        self._supports_temperature = value

    def get_ctrl_msg_id_bytes(self):
        """
        Control packets need a number that gets incremented, it is used as a type of msg ID and
        in calculating the checksum. Result is mod 256 in order to keep it within 0-255.
        """
        lp = f"{self.lp}get_ctrl_msg_id_bytes:"
        id_byte, rollover_byte = self.control_bytes
        # logger.debug(f"{lp} Getting control message ID bytes: ctrl_byte={id_byte} rollover_byte={rollover_byte}")
        id_byte += 1
        if id_byte > 255:
            id_byte = id_byte % 256
            rollover_byte += 1

        self.control_bytes = [id_byte, rollover_byte]
        # logger.debug(f"{lp} new data: ctrl_byte={id_byte} rollover_byte={rollover_byte} // {self.control_bytes=}")
        return self.control_bytes

    async def set_power(self, state: int):
        """
        Send raw data to control device state (1=on, 0=off).

            If the device receives the msg and changes state, every http device connected will send
            a 0x83 internal status packet, which we use to change HASS device state.
        """
        lp = f"{self.lp}set_power:"
        if state not in (0, 1):
            logger.error(f"{lp} Invalid state! must be 0 or 1")
            return
        header = [0x73, 0x00, 0x00, 0x00, 0x1F]
        inner_struct = [
            0x7E,
            "ctrl_byte",
            0x00,
            0x00,
            0x00,
            0xF8,
            0xD0,
            0x0D,
            0x00,
            "ctrl_bye",
            0x00,
            0x00,
            0x00,
            0x00,
            self.id,
            0x00,
            0xD0,
            0x11,
            0x02,
            state,
            0x00,
            0x00,
            "checksum",
            0x7E,
        ]
        # pick random http devices to send the command to
        # it should bridge the command over btle to the device ID
        bridge_devices: List["CyncHTTPDevice"] = random.sample(
            list(g.server.http_devices.values()), k=min(3, len(g.server.http_devices))
        )
        str_devices = " ".join([x.address for x in bridge_devices])
        logger.debug(
            f"{lp} Sending power state command, current: {self.state} - new: {state} to "
            f"http devices: {str_devices}"
        )
        tasks: List[Optional[asyncio.Task]] = []
        ts = time.time()
        ctrl_idxs = 1, 9
        for i in range(2):
            for bridge_device in bridge_devices:
                if bridge_device.ready_to_control is True:
                    payload = list(header)
                    payload.extend(bridge_device.queue_id)
                    payload.extend(bytes([0x00, 0x00, 0x00]))
                    ctrl_byte = bridge_device.get_ctrl_msg_id_bytes()[0]
                    checksum = ((ctrl_byte - 64) + state + self.id) % 256
                    inner_struct[ctrl_idxs[0]] = ctrl_byte
                    inner_struct[ctrl_idxs[1]] = ctrl_byte
                    inner_struct[-2] = checksum
                    payload.extend(inner_struct)
                    # await bridge_device.write(b)
                    tasks.append(loop.create_task(bridge_device.write(bytes(payload))))
                else:
                    logger.debug(
                        f"{lp} Skipping device: {bridge_device.address} not ready to control"
                    )
            if i == 0:
                await asyncio.sleep(0.1)
        if tasks:
            await asyncio.gather(*tasks)
        elapsed = time.time() - ts
        logger.debug(f"{lp} set_power took {elapsed:.5f} seconds")

    async def set_brightness(self, bri: int):
        """
        Send raw data to control device brightness (0-100)

            If the device receives the msg and changes state, every http device connected will send
            a 0x83 internal status packet, which we use to change HASS device state.
        """
        """
        73 00 00 00 22 37 96 24 69 60 48 00 7e 17 00 00  s..."7.$i`H.~...
        00 f8 f0 10 00 17 00 00 00 00 07 00 f0 11 02 01  ................
        27 ff ff ff ff 45 7e
        """
        lp = f"{self.lp}set_brightness:"
        header = [115, 0, 0, 0, 34]
        inner_struct = [
            126,
            "ctrl_byte",
            0,
            0,
            0,
            248,
            240,
            16,
            0,
            "ctrl_byte",
            0,
            0,
            0,
            0,
            self.id,
            0,
            240,
            17,
            2,
            1,
            bri,
            255,
            255,
            255,
            255,
            "checksum",
            126,
        ]
        # pick random http devices to send the command to
        # it should bridge the command over btle to the device ID
        bridge_devices: List["CyncHTTPDevice"] = random.sample(
            list(g.server.http_devices.values()), k=min(3, len(g.server.http_devices))
        )
        str_devices = " ".join([x.address for x in bridge_devices])
        logger.debug(
            f"{lp} Sending brightness command, current: {self._brightness} new: {bri} to http devices: {str_devices}"
        )
        tasks: List[Optional[asyncio.Task]] = []
        ts = time.time()
        ctrl_idxs = 1, 9
        # sometimes the device doesn't respond to the first command, so we send it twice with a small delay between them
        for i in range(2):
            for bridge_device in bridge_devices:
                if bridge_device.ready_to_control is True:
                    payload = list(header)
                    payload.extend(bridge_device.queue_id)
                    payload.extend(bytes([0x00, 0x00, 0x00]))
                    ctrl_byte = bridge_device.get_ctrl_msg_id_bytes()[0]
                    checksum = (ctrl_byte + bri + self.id) % 256
                    inner_struct[ctrl_idxs[0]] = ctrl_byte
                    inner_struct[ctrl_idxs[1]] = ctrl_byte
                    inner_struct[-2] = checksum
                    payload.extend(inner_struct)
                    # await bridge_device.write(b)
                    tasks.append(loop.create_task(bridge_device.write(bytes(payload))))
                else:
                    logger.debug(
                        f"{lp} Skipping device: {bridge_device.address} (id: {id(bridge_device)}) not ready to control"
                    )
            if i == 0:
                await asyncio.sleep(0.1)
        # Wait for all tasks to complete
        if tasks:
            await asyncio.gather(*tasks)
        elapsed = time.time() - ts
        logger.debug(f"{lp} set_brightness took {elapsed:.5f} seconds")

    async def set_temperature(self, temp: int):
        """
        Send raw data to control device white temperature (0-100)

            If the device receives the msg and changes state, every http device connected will send
            a 0x83 internal status packet, which we use to change HASS device state.
        """
        """
        73 00 00 00 22 37 96 24 69 60 8d 00 7e 36 00 00  s..."7.$i`..~6..
        00 f8 f0 10 00 36 00 00 00 00 07 00 f0 11 02 01  .....6..........
        ff 48 00 00 00 88 7e                             .H....~
            
                checksum = 0x88 = 136
            0x36 0x48 0x07 = 54 + 72 + 7 = 133 (needs + 3)
        """
        lp = f"{self.lp}set_temperature:"
        header = [115, 0, 0, 0, 34]
        inner_struct = [
            126,
            "ctrl_msg_id[0]",
            0,
            0,
            0,
            248,
            240,
            16,
            0,
            "ctrl_msg_id[0]",
            0,
            0,
            0,
            0,
            self.id,
            0,
            240,
            17,
            2,
            1,
            0xFF,
            temp,
            0x00,
            0x00,
            0x00,
            "checksum",
            126,
        ]
        # pick random http devices to send the command to
        # it will bridge the command over btle to the specified device ID
        bridge_devices: List["CyncHTTPDevice"] = random.sample(
            list(g.server.http_devices.values()), k=min(3, len(g.server.http_devices))
        )
        str_devices = " ".join([x.address for x in bridge_devices])
        logger.debug(
            f"{lp} Sending white temperature command, current: {self.temperature} - new: {temp} to http devices: {str_devices}"
        )
        tasks: List[Optional[asyncio.Task]] = []
        ts = time.time()
        ctrl_idxs = 1, 9
        for i in range(2):
            for bridge_device in bridge_devices:
                if bridge_device.ready_to_control is True:
                    payload = list(header)
                    payload.extend(bridge_device.queue_id)
                    payload.extend(bytes([0x00, 0x00, 0x00]))
                    ctrl_byte = bridge_device.get_ctrl_msg_id_bytes()[0]
                    checksum = ((ctrl_byte + temp + self.id) + 3) % 256
                    inner_struct[ctrl_idxs[0]] = ctrl_byte
                    inner_struct[ctrl_idxs[1]] = ctrl_byte
                    inner_struct[-2] = checksum
                    payload.extend(inner_struct)
                    # await bridge_device.write(b)
                    tasks.append(loop.create_task(bridge_device.write(bytes(payload))))
                else:
                    logger.debug(
                        f"{lp} Skipping device: {bridge_device.address} not ready to control"
                    )
            if i == 0:
                await asyncio.sleep(0.1)
        if tasks:
            await asyncio.gather(*tasks)
        elapsed = time.time() - ts
        logger.debug(f"{lp} set_temperature took {elapsed:.5f} seconds")

    async def set_rgb(self, red: int, green: int, blue: int):
        """
        Send raw data to control device RGB color (0-255 for each channel).

            If the device receives the msg and changes state, every http device connected will send
            a 0x83 internal status packet, which we use to change HASS device state.
        """
        """
         73 00 00 00 22 37 96 24 69 60 79 00 7e 2b 00 00  s..."7.$i`y.~+..
         00 f8 f0 10 00 2b 00 00 00 00 07 00 f0 11 02 01  .....+..........
         ff fe 00 fb ff 2d 7e                             .....-~

                checksum = 45
            2b 07 00 fb ff = 43 + 7 + 0 + 251 + 255 = 556 (needs + 1)
        """
        lp = f"{self.lp}set_rgb:"
        header = [115, 0, 0, 0, 34]
        inner_struct = [
            126,
            "ctrl_msg_id[0]",
            0,
            0,
            0,
            248,
            240,
            16,
            0,
            "ctrl_msg_id[0]",
            0,
            0,
            0,
            0,
            self.id,
            0,
            240,
            17,
            2,
            1,
            255,
            254,
            red,
            green,
            blue,
            "checksum",
            126,
        ]
        # pick random http devices to send the command to
        # it should bridge the command over btle to the device ID
        bridge_devices: List["CyncHTTPDevice"] = random.sample(
            list(g.server.http_devices.values()), k=min(3, len(g.server.http_devices))
        )
        str_devices = " ".join([x.address for x in bridge_devices])
        logger.debug(
            f"{lp} Sending RGB command, current: {self.red}, {self.green}, {self.blue} - new: {red}, {green}, {blue} to http devices {str_devices}"
        )
        tasks: List[Optional[asyncio.Task]] = []
        ts = time.time()
        ctrl_idxs = 1, 9
        for i in range(2):
            for bridge_device in bridge_devices:
                if bridge_device.ready_to_control is True:
                    payload = list(header)
                    payload.extend(bridge_device.queue_id)
                    payload.extend(bytes([0x00, 0x00, 0x00]))
                    ctrl_byte = bridge_device.get_ctrl_msg_id_bytes()[0]
                    checksum = ((ctrl_byte + self.id + red + green + blue) + 1) % 256
                    inner_struct[ctrl_idxs[0]] = ctrl_byte
                    inner_struct[ctrl_idxs[1]] = ctrl_byte
                    inner_struct[-2] = checksum
                    payload.extend(inner_struct)
                    # await bridge_device.write(b)
                    tasks.append(loop.create_task(bridge_device.write(bytes(payload))))
                else:
                    logger.debug(
                        f"{lp} Skipping device: {bridge_device.address} not ready to control"
                    )
            if i == 0:
                await asyncio.sleep(0.1)
        if tasks:
            await asyncio.gather(*tasks)
        elapsed = time.time() - ts
        logger.debug(f"{lp} set_rgb took {elapsed:.5f} seconds")

    @property
    def online(self):
        return self._online

    @online.setter
    def online(self, value: bool):
        if value != self._online:
            self._online = value
            loop.create_task(g.mqtt.pub_online(self.id, value))

    def is_bt_only(self):
        """From my observations, if the wifi mac does not start with the same 3 groups as the mac, it's BT only."""
        if self.wifi_mac == "00:01:02:03:04:05":
            return True
        elif self.mac is not None and self.wifi_mac is not None:

            if str(self.mac)[:8].casefold() != str(self.wifi_mac)[:8].casefold():
                return True
        return False

    # noinspection PyTypeChecker
    @property
    def current_status(self) -> List[int]:
        """
        Return the current status of the device as a list

        :return: [state, brightness, temperature, red, green, blue]
        """
        return [
            self._state,
            self._brightness,
            self._temperature,
            self._r,
            self._g,
            self._b,
        ]

    @property
    def status(self) -> DeviceStatus:
        return self._status

    @status.setter
    def status(self, value: DeviceStatus):
        if self._status != value:
            self._status = value

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, value: Union[int, bool, str]):
        """
        Set the state of the device.
        Accepts int, bool, or str. 0, 'f', 'false', 'off', 'no', 'n' are off. 1, 't', 'true', 'on', 'yes', 'y' are on.
        """
        _t = (1, "t", "true", "on", "yes", "y")
        _f = (0, "f", "false", "off", "no", "n")
        if isinstance(value, str):
            value = value.casefold()
        elif isinstance(value, (bool, float)):
            value = int(value)
        elif isinstance(value, int):
            pass
        else:
            raise TypeError(f"Invalid type for state: {type(value)}")

        if value in _t:
            value = 1
        elif value in _f:
            value = 0
        else:
            raise ValueError(f"Invalid value for state: {value}")

        if value != self._state:
            self._state = value

    @property
    def brightness(self):
        return self._brightness

    @brightness.setter
    def brightness(self, value: int):
        if value < 0 or value > 100:
            raise ValueError(f"Brightness must be between 0 and 100, got: {value}")
        if value != self._brightness:
            self._brightness = value

    @property
    def temperature(self):
        return self._temperature

    @temperature.setter
    def temperature(self, value: int):
        if value < 0 or value > 255:
            raise ValueError(f"Temperature must be between 0 and 255, got: {value}")
        if value != self._temperature:
            self._temperature = value

    @property
    def red(self):
        return self._r

    @red.setter
    def red(self, value: int):
        if value < 0 or value > 255:
            raise ValueError(f"Red must be between 0 and 255, got: {value}")
        if value != self._r:
            self._r = value

    @property
    def green(self):
        return self._g

    @green.setter
    def green(self, value: int):
        if value < 0 or value > 255:
            raise ValueError(f"Green must be between 0 and 255, got: {value}")
        if value != self._g:
            self._g = value

    @property
    def blue(self):
        return self._b

    @blue.setter
    def blue(self, value: int):
        if value < 0 or value > 255:
            raise ValueError(f"Blue must be between 0 and 255, got: {value}")
        if value != self._b:
            self._b = value

    @property
    def rgb(self):
        """Return the RGB color as a list"""
        return [self._r, self._g, self._b]

    @rgb.setter
    def rgb(self, value: List[int]):
        if len(value) != 3:
            raise ValueError(f"RGB value must be a list of 3 integers, got: {value}")
        if value != self.rgb:
            self._r, self._g, self._b = value

    def __repr__(self):
        return f"<CyncDevice: {self.id}>"

    def __str__(self):
        return f"CyncDevice:{self.id}:"


class CyncLanServer:
    """A class to represent a Cync LAN server that listens for connections from Cync WiFi devices.
    The WiFi devices can proxy messages to BlueTooth devices. The WiFi devices act as hubs for the BlueTooth mesh.
    """

    devices: Dict[int, CyncDevice] = {}
    http_devices: Dict[str, Optional["CyncHTTPDevice"]] = {}
    shutting_down: bool = False
    host: str
    port: int
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    loop: Union[asyncio.AbstractEventLoop, uvloop.Loop]
    _server: Optional[asyncio.Server] = None
    lp: str = "CyncServer:"

    def __init__(
        self,
        host: str,
        port: int,
        cert_file: Optional[str] = None,
        key_file: Optional[str] = None,
    ):
        self.mesh_info_loop_task: Optional[asyncio.Task] = None
        global g

        self.ssl_context: Optional[ssl.SSLContext] = None
        self.mesh_loop_started: bool = False
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.loop: Union[asyncio.AbstractEventLoop, uvloop.Loop] = (
            asyncio.get_event_loop()
        )
        self.known_ids: List[Optional[int]] = []
        g.server = self

    async def close_http_device(self, device: "CyncHTTPDevice"):
        """Gracefully close HTTP device; async task and reader/writer"""
        # check if the receive task is running or in done/exception state.
        lp_id = f"[{device.id}]" if device.id is not None else ""
        lp = f"{self.lp}remove_http_device:{device.address}{lp_id}:"
        dev_id = id(device)
        logger.debug(f"{lp} Closing HTTP device: {dev_id}")
        if (_r_task := device.tasks.receive) is not None:
            if _r_task.done():
                logger.debug(
                    f"{lp} existing receive task ({_r_task.get_name()}) is done, no need to cancel..."
                )
            else:
                logger.debug(
                    f"{lp} existing receive task is running (name: {_r_task.get_name()}), cancelling..."
                )
                await asyncio.sleep(1)
                _r_task.cancel("Gracefully closing HTTP device")
                await asyncio.sleep(0)
                if _r_task.cancelled():
                    logger.debug(
                        f"{lp} existing receive task was cancelled successfully"
                    )
                else:
                    logger.warning(f"{lp} existing receive task was not cancelled!")
        else:
            logger.debug(f"{lp} no existing receive task found!")

        # existing reader is closed, no sense in feeding it EOF, just remove it
        device.reader = None
        # Go through the motions to gracefully close the writer
        try:
            device.writer.close()
            await device.writer.wait_closed()
        except Exception as writer_close_exc:
            logger.error(f"{lp} Error closing writer: {writer_close_exc}")
        device.writer = None
        logger.debug(f"{lp} Removed HTTP device from server")

    async def create_ssl_context(self):
        # Allow the server to use a self-signed certificate
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
        # turn off all the SSL verification
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        # ascertained from debugging using socat
        ciphers = [
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES256-SHA384",
            "ECDHE-RSA-AES128-SHA256",
            "ECDHE-RSA-AES256-SHA",
            "ECDHE-RSA-AES128-SHA",
            "ECDHE-RSA-DES-CBC3-SHA",
            "AES256-GCM-SHA384",
            "AES128-GCM-SHA256",
            "AES256-SHA256",
            "AES128-SHA256",
            "AES256-SHA",
            "AES128-SHA",
            "DES-CBC3-SHA",
        ]
        ssl_context.set_ciphers(":".join(ciphers))
        return ssl_context

    async def parse_status(self, raw_state: bytes):
        """Extracted status packet parsing, handles mqtt publishing and device state changes."""
        _id = raw_state[0]
        state = raw_state[1]
        brightness = raw_state[2]
        temp = raw_state[3]
        r = raw_state[4]
        _g = raw_state[5]
        b = raw_state[6]
        connected_to_mesh = 1
        # check if len is enough for good byte, it is optional
        if len(raw_state) > 7:
            # The last byte seems to indicate if the bulb is online or offline
            connected_to_mesh = raw_state[7]

        device = g.server.devices.get(_id)
        if device is None:
            logger.warning(
                f"Device ID: {_id} not found in devices! device may be disabled in config file or consider re-exporting your Cync account devices "
                f"or there is unknown data!"
            )
            return
        # set the device status, can be used when hass comes back online via last will message

        if connected_to_mesh == 0:
            # This usually happens when a device loses power/connection.
            # this device is gone, need to mark it offline.
            # todo: sometimes its a false report. Maybe collect these
            #  and parse them every mesh info loop and use a voting system
            bt_only = device.is_bt_only()
            dev_type = "WiFi/BT" if not bt_only else "BT only"
            if device.online:
                logger.warning(
                    f"{self.lp} Device ID: {_id} ({device.name}) is {dev_type}, it seems to have been removed from the "
                    f"mesh (lost power/connection), setting offline..."
                )
            device.online = False
            if bt_only:
                pass
            elif not bt_only:
                # dont remove the http device, sometimes the mesh says devices are offline when they arent
                pass

        else:
            device.online = True
            # create a status with existing data, change along the way for publishing over mqtt
            device.status = new_state = DeviceStatus(
                state=device.state,
                brightness=device.brightness,
                temperature=device.temperature,
                red=device.red,
                green=device.green,
                blue=device.blue,
            )
            whats_changed = []
            # temp is 0-100, if > 100, RGB data has been sent, otherwise its on/off, brightness or temp data
            rgb_data = False
            if temp > 100:
                rgb_data = True
            # device class has properties that have logic to only run on changes.
            # fixme: need to make a bulk_change method to prevent multiple mqtt messages
            curr_status = device.current_status
            if curr_status == [state, brightness, temp, r, _g, b]:
                (
                    logger.debug(f"{device.lp} NO CHANGES TO DEVICE STATUS")
                    if CYNC_RAW is True
                    else None
                )
            else:
                # find the differences
                if state != device.state:
                    whats_changed.append("state")
                    new_state.state = state
                if brightness != device.brightness:
                    whats_changed.append("brightness")
                    new_state.brightness = brightness
                if temp != device.temperature:
                    whats_changed.append("temperature")
                    new_state.temperature = temp
                if rgb_data is True:
                    if r != device.red:
                        whats_changed.append("red")
                        new_state.red = r
                    if _g != device.green:
                        whats_changed.append("green")
                        new_state.green = _g
                    if b != device.blue:
                        whats_changed.append("blue")
                        new_state.blue = b
            # if whats_changed:
            #     logger.debug(
            #         f"{device.lp} CHANGES TO DEVICE STATUS: {', '.join(whats_changed)} -> {new_state} "
            #         f"// OLD = {curr_status}"
            #     )
            if g.mqtt.pub_queue is None:
                logger.critical(
                    f"{self.lp} Something is wrong! MQTT pub_queue is None! "
                    f"NEED TO IMPLEMENT A RESTART OR GRACEFUL KILL"
                )

            g.mqtt.pub_queue.put_nowait((device.id, new_state))
            device.state = state
            device.brightness = brightness
            device.temperature = temp
            if rgb_data is True:
                device.red = r
                device.green = _g
                device.blue = b
            g.server.devices[device.id] = device

    async def mesh_info_loop(self):
        """A function that is to be run as an async task to ask each http device for its mesh info"""
        lp = f"{self.lp}mesh_loop:"
        logger.debug(
            f"{lp} Starting, after first run delay of 5 seconds, will run every "
            f"{CYNC_MESH_CHECK_INTERVAL} seconds"
        )
        self.mesh_loop_started = True
        await asyncio.sleep(5)
        while True:
            try:
                if self.shutting_down:
                    logger.info(
                        f"{lp} Server is shutting/shut down, exiting mesh info loop task..."
                    )
                    break

                mesh_info_list = []
                offline_ids = []
                previous_online_ids = list(self.known_ids)
                self.known_ids = []
                # logger.debug(f"{lp} // {previous_online_ids = }")
                ids_from_config = g.cync_lan.ids_from_config
                if not ids_from_config:
                    logger.warning(
                        f"{lp} No device IDs found in config file! Can not run mesh info loop. Exiting..."
                    )
                    os.kill(os.getpid(), signal.SIGTERM)

                http_dev_keys = list(self.http_devices.keys())
                # ask all devices for their mesh info
                logger.debug(
                    f"{lp} Asking all ({len(http_dev_keys)}) connected HTTP devices for their "
                    f"BTLE mesh info: {', '.join(http_dev_keys).rstrip(',')}"
                )
                for dev_addy in http_dev_keys:
                    http_dev = self.http_devices.get(dev_addy)
                    if http_dev is None:
                        logger.warning(f"{lp} HTTP device not found: {dev_addy}")
                        continue
                    await http_dev.ask_for_mesh_info()
                # wait for replies
                sleep_time = 1.25
                await asyncio.sleep(sleep_time)
                for dev_addy in http_dev_keys:
                    http_dev = self.http_devices.get(dev_addy)
                    if http_dev is None:
                        logger.warning(f"{lp} HTTP device not found: {dev_addy}")
                        continue
                    if http_dev.known_device_ids:
                        self.known_ids.extend(http_dev.known_device_ids)
                        mesh_info_list.append(http_dev.mesh_info)
                    else:
                        logger.debug(
                            f"{lp} No known device IDs for: {http_dev.address} after a {sleep_time}s sleep"
                        )

                self.known_ids = list(set(self.known_ids))
                availability_info = defaultdict(bool)
                _ids_from_cfg = []
                for cfg_id in ids_from_config:
                    __dev_id = int(cfg_id.split("-")[1])
                    _ids_from_cfg.append(__dev_id)
                    availability_info[__dev_id] = __dev_id in self.known_ids
                    if not availability_info[__dev_id]:
                        offline_ids.append(__dev_id)
                    await g.mqtt.pub_online(__dev_id, availability_info[__dev_id])

                offline_str = (
                    f" offline ({len(offline_ids)}): {sorted(offline_ids)} //"
                    if offline_ids
                    else ""
                )

                for known_id in self.known_ids:
                    if known_id not in _ids_from_cfg:
                        logger.warning(
                            f"{lp} Device {known_id} not found in config file! You may need to "
                            f"export the devices again OR there is unknown data to decode."
                        )
                    (
                        logger.debug(
                            f"{lp} No known device IDs found in ANY HTTP devices: {self.http_devices.keys()}"
                        )
                        if not self.known_ids
                        else None
                    )

                diff_ = set(previous_online_ids) - set(self.known_ids)
                (
                    logger.debug(
                        f"{lp} No change to devices.{offline_str} online ({len(self.known_ids)}): "
                        f"{sorted(self.known_ids)}"
                    )
                    if self.known_ids == previous_online_ids
                    else logger.debug(
                        f"{lp} Online devices has changed! (new: {diff_}){offline_str} online "
                        f"({len(self.known_ids)}): {self.known_ids}"
                    )
                )

                votes = defaultdict(int)
                for mesh_info in mesh_info_list:
                    if mesh_info is not None:
                        status_list = mesh_info.status
                        for dev_status in status_list:
                            votes[str(dev_status)] += 1

                sorted_votes = dict(
                    sorted(votes.items(), key=lambda item: item[1], reverse=True)
                )
                unique_dict = {}
                for status_, votes_ in sorted_votes.items():
                    status_ = ast.literal_eval(status_)
                    if status_[0] not in unique_dict:
                        unique_dict[status_[0]] = {votes_: status_}

                for _id, vote_status_dict in unique_dict.items():
                    for voted_best_status in vote_status_dict.values():
                        bds = DeviceStatus(
                            state=voted_best_status[1],
                            brightness=voted_best_status[2],
                            temperature=voted_best_status[3],
                            red=voted_best_status[4],
                            green=voted_best_status[5],
                            blue=voted_best_status[6],
                        )
                        await g.mqtt.parse_device_status(_id, bds)

                # Check mqtt pub and sub worker tasks, if they are done or exception, recreate
                await self.check_mqtt_tasks()

                await asyncio.sleep(CYNC_MESH_CHECK_INTERVAL)

            except asyncio.CancelledError as ce:
                logger.debug(f"{lp} Task cancelled, breaking out of loop: {ce}")
                break
            except TimeoutError as to_exc:
                logger.error(f"{lp} Timeout error in mesh info loop: {to_exc}")
            except Exception as e:
                logger.error(f"{lp} Error in mesh info loop: {e}", exc_info=True)

        self.mesh_loop_started = False
        logger.info(f"\n\n{lp} end of mesh_info_loop()\n\n")

    @staticmethod
    async def check_mqtt_tasks():
        mqtt_tasks = g.mqtt.tasks
        remove_idx = []
        idx = 0
        for task in mqtt_tasks:
            if task.get_name() in ("pub_worker", "sub_worker"):
                new_task = (
                    g.mqtt.sub_worker
                    if task.get_name() == "sub_worker"
                    else g.mqtt.pub_worker
                )
                new_queue = (
                    g.mqtt.sub_queue
                    if task.get_name() == "sub_worker"
                    else g.mqtt.pub_queue
                )
                if task.done():
                    logger.error(f"MQTT task: {task.get_name()} is done! Recreating...")
                    task.cancel()
                    await asyncio.sleep(0.5)
                    g.mqtt.tasks.append(
                        asyncio.create_task(new_task(new_queue), name=task.get_name())
                    )
                    remove_idx.append(idx)
            idx += 1
        if remove_idx:
            for idx in remove_idx:
                z = g.mqtt.tasks.pop(idx)
                del z
        else:
            # logger.debug(f"{lp} MQTT sub/pub tasks are still running")
            pass

    async def start(self):
        logger.debug("%s Starting, creating SSL context..." % self.lp)
        try:
            self.ssl_context = await self.create_ssl_context()
            self._server = await asyncio.start_server(
                self._register_new_connection,
                host=self.host,
                port=self.port,
                ssl=self.ssl_context,  # Pass the SSL context to enable SSL/TLS
            )

        except Exception as e:
            logger.error(f"{self.lp} Failed to start server: {e}", exc_info=True)
            os.kill(os.getpid(), signal.SIGTERM)
        else:
            logger.info(
                f"{self.lp} Started, bound to {self.host}:{self.port} - Waiting for connections, if you dont"
                f" see any, check your DNS redirection, VLAN and firewall settings."
            )
            try:
                async with self._server:
                    await self._server.serve_forever()
            except asyncio.CancelledError as ce:
                logger.debug(
                    "%s Server cancelled (task.cancel() ?): %s" % (self.lp, ce)
                )
            except Exception as e:
                logger.error("%s Server Exception: %s" % (self.lp, e), exc_info=True)

            logger.info(f"{self.lp} end of start()")

    async def stop(self):
        logger.debug(
            "%s stop() called, closing each http communication device..." % self.lp
        )
        self.shutting_down = True
        # check tasks
        device: "CyncHTTPDevice"
        devices = list(self.http_devices.values())
        lp = f"{self.lp}:close:"
        if devices:
            for device in devices:
                try:
                    await device.close()
                except Exception as e:
                    logger.error("%s Error closing device: %s" % (lp, e), exc_info=True)
                else:
                    logger.debug(f"{lp} Device closed")
        else:
            logger.debug(f"{lp} No devices to close!")

        if self._server:
            if self._server.is_serving():
                logger.debug("%s currently running, shutting down NOW..." % lp)
                self._server.close()
                await self._server.wait_closed()
                logger.debug("%s shut down!" % lp)
            else:
                logger.debug("%s not running!" % lp)

        # cancel tasks
        if self.mesh_info_loop_task:
            if self.mesh_info_loop_task.done():
                pass
            else:
                self.mesh_info_loop_task.cancel()
                await self.mesh_info_loop_task
        for task in global_tasks:
            if task.done():
                continue
            logger.debug("%s Cancelling task: %s" % (lp, task))
            task.cancel()
        # todo: cleaner exit

        logger.debug("%s stop() complete, calling loop.stop()" % lp)
        self.loop.stop()

    async def _register_new_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        client_addr: str = writer.get_extra_info("peername")[0]
        lp = f"{self.lp}new_conn:{client_addr}:"
        if self.shutting_down is True:
            logger.warning(
                f"{lp} Server is shutting/shut down, rejecting new connection from: {client_addr}"
            )
            return
        else:
            logger.info(f"{lp} New HTTP session!")

        new_device = CyncHTTPDevice(reader, writer, address=client_addr)
        existing_device = self.http_devices.pop(client_addr, None)
        # get memory address of the new device to use as UID in task name
        new_device_id = id(new_device)
        self.http_devices[client_addr] = new_device
        new_device.tasks.receive = self.loop.create_task(
            new_device.receive_task(), name=f"receive_task-{new_device_id}"
        )
        if self.mesh_loop_started is False:
            # Start mesh info loop
            self.mesh_info_loop_task = asyncio.create_task(self.mesh_info_loop())

        # Check if the device is already registered
        if existing_device is not None:
            existing_device_id = id(existing_device)
            logger.debug(
                f"{lp} Existing device found ({existing_device_id}), gracefully killing..."
            )
            # await self.close_http_device(existing_device)
            del existing_device


class CyncLAN:
    """Wrapper class to manage the Cync LAN server and MQTT client."""

    loop: uvloop.Loop = None
    mqtt_client: "MQTTClient" = None
    server: CyncLanServer = None
    lp: str = "CyncLAN:"
    # devices pulled in from the config file.
    cfg_devices: dict = {}

    def __init__(self, cfg_file: Path):
        global g

        self._ids_from_config: List[Optional[str]] = []
        g.cync_lan = self
        self.loop = uvloop.new_event_loop()
        if CYNC_DEBUG is True:
            self.loop.set_debug(True)
        asyncio.set_event_loop(self.loop)
        self.cfg_devices = self.parse_config(cfg_file)
        self.mqtt_client = MQTTClient(CYNC_MQTT_URL)

    @property
    def ids_from_config(self):
        return self._ids_from_config

    def parse_config(self, cfg_file: Path):
        """Parse the exported Cync config file and create devices from it.

        Exported config created by scraping cloud API. Devices must already be added to your Cync account.
        If you add new or delete existing devices, you will need to re-export the config.
        """
        global CYNC_MQTT_URL, CYNC_CERT, CYNC_KEY, CYNC_HOST, CYNC_PORT, g

        logger.debug("%s reading devices from exported Cync config file..." % self.lp)
        try:
            raw_config = yaml.safe_load(cfg_file.read_text())
        except Exception as e:
            logger.error(f"{self.lp} Error reading config file: {e}", exc_info=True)
            raise e
        devices = {}
        if "mqtt_url" in raw_config:
            CYNC_MQTT_URL = raw_config["mqtt_url"]
            logger.info(f"{self.lp} MQTT URL set by config file to: {CYNC_MQTT_URL}")
        if "cert" in raw_config:
            CYNC_CERT = raw_config["cert_file"]
            logger.info(f"{self.lp} Cert file set by config file to: {CYNC_CERT}")
        if "key" in raw_config:
            CYNC_KEY = raw_config["key_file"]
            logger.info(f"{self.lp} Key file set by config file to: {CYNC_KEY}")
        if "host" in raw_config:
            CYNC_HOST = raw_config["host"]
            logger.info(f"{self.lp} Host set by config file to: {CYNC_HOST}")
        if "port" in raw_config:
            CYNC_PORT = raw_config["port"]
            logger.info(f"{self.lp} Port set by config file to: {CYNC_PORT}")
        for cfg_name, cfg in raw_config["account data"].items():
            home_id = cfg["id"]
            if "devices" not in cfg:
                logger.warning(
                    f"{self.lp} No devices found in config for: {cfg_name} (ID: {home_id}), skipping..."
                )
                continue
            if "name" not in cfg:
                cfg["name"] = f"HomeID_{home_id}"
            # Create devices
            for cync_id, cync_device in cfg["devices"].items():
                cync_device: dict
                device_name = (
                    cync_device["name"]
                    if "name" in cync_device
                    else f"device_{cync_id}"
                )
                if "enabled" in cync_device:
                    if cync_device["enabled"] is False:
                        logger.debug(
                            f"{self.lp} Device '{device_name}' (ID: {cync_id}) is disabled in config, skipping..."
                        )
                        continue
                self._ids_from_config.append(f"{home_id}-{cync_id}")

                fw_version = cync_device["fw"] if "fw" in cync_device else None
                new_device = CyncDevice(
                    name=device_name,
                    cync_id=cync_id,
                    fw_version=fw_version,
                    home_id=home_id,
                )
                for attrset in (
                    "is_plug",
                    "supports_temperature",
                    "supports_rgb",
                    "mac",
                    "wifi_mac",
                    "ip",
                    "type",
                ):
                    if attrset in cync_device:
                        setattr(new_device, attrset, cync_device[attrset])
                devices[cync_id] = new_device
                # logger.debug(f"{self.lp} Created device (hass_id: {new_device.hass_id}) (home_id: {new_device.home_id}) (device_id: {new_device.id}): {new_device}")

        return devices

    def start(self):
        global global_tasks

        self.server = CyncLanServer(CYNC_HOST, CYNC_PORT, CYNC_CERT, CYNC_KEY)
        self.server.devices = self.cfg_devices
        server_task = self.loop.create_task(self.server.start(), name="server_start")

        mqtt_task = self.loop.create_task(self.mqtt_client.start(), name="mqtt_start")
        global_tasks.extend([server_task, mqtt_task])

    def stop(self):
        global global_tasks
        logger.debug(
            f"{self.lp} stop() called, calling server and MQTT client stop()..."
        )
        if self.server:
            self.loop.create_task(self.server.stop())
        if self.mqtt_client:
            self.loop.create_task(self.mqtt_client.stop())

    def signal_handler(self, sig: int):
        logger.info("Caught signal %d, trying a clean shutdown" % sig)
        self.stop()


class CyncHTTPDevice:
    """
    A class to interact with an HTTP Cync device. It is an async socket reader/writer.

    """

    lp: str = "HTTPDevice:"
    known_device_ids: List[int] = []
    tasks: Tasks = Tasks()
    reader: Optional[asyncio.StreamReader]
    writer: Optional[asyncio.StreamWriter]
    messages: Messages
    # keep track of msg ids and if we finished reading data, if not, we need to append the data and then parse it
    read_cache = []
    needs_more_data = False

    def __init__(
        self,
        reader: Optional[asyncio.StreamReader] = None,
        writer: Optional[asyncio.StreamWriter] = None,
        address: Optional[str] = None,
    ):
        self.name: Optional[str] = None
        self.first_83_packet_checksum: Optional[int] = None
        self.ready_to_control = False
        self.network_version_str: Optional[str] = None
        self.inc_bytes: Optional[Union[int, bytes, str]] = None
        self.version: Optional[int] = None
        self.version_str: Optional[str] = None
        self.network_version: Optional[int] = None
        self.device_types: Optional[dict] = None
        self.device_type_id: Optional[int] = None
        self.device_timestamp: Optional[str] = None
        self.capabilities: Optional[dict] = None
        self.last_xc3_request: Optional[float] = None
        self.messages = Messages()
        self.mesh_info: Optional[MeshInfo] = None
        self.parse_mesh_status = False

        self.id: Optional[int] = None
        self.xa3_msg_id: bytes = bytes([0x00, 0x00, 0x00])
        if address is None:
            raise ValueError("Address or ID must be provided to CyncDevice constructor")
        # data we might want later?
        self.queue_id: bytes = b""
        self.address: Optional[str] = address
        self.read_lock = asyncio.Lock()
        self.write_lock = asyncio.Lock()
        self._reader: asyncio.StreamReader = reader
        self._writer: asyncio.StreamWriter = writer
        self._closing = False
        # Create a ref to the mqtt queues
        self.mqtt_pub_queue: asyncio.Queue = g.mqtt.pub_queue
        self.mqtt_sub_queue: asyncio.Queue = g.mqtt.sub_queue
        logger.debug(f"{self.lp} Created new device: {address}")
        self.lp = f"{self.address}:"
        self.control_bytes = [0x00, 0x00]

    def get_ctrl_msg_id_bytes(self):
        """
        Control packets need a number that gets incremented, it is used as a type of msg ID and
        in calculating the checksum. Result is mod 256 in order to keep it within 0-255.
        """
        lp = f"{self.lp}get_ctrl_msg_id_bytes:"
        id_byte, rollover_byte = self.control_bytes
        # logger.debug(f"{lp} Getting control message ID bytes: ctrl_byte={id_byte} rollover_byte={rollover_byte}")
        id_byte += 1
        if id_byte > 255:
            id_byte = id_byte % 256
            rollover_byte += 1

        self.control_bytes = [id_byte, rollover_byte]
        # logger.debug(f"{lp} new data: ctrl_byte={id_byte} rollover_byte={rollover_byte} // {self.control_bytes=}")
        return self.control_bytes

    @property
    def closing(self):
        return self._closing

    @closing.setter
    def closing(self, value: bool):
        self._closing = value

    async def parse_raw_data(self, data: bytes):
        """Extract single packets from raw data stream using metadata"""
        data_len = len(data)
        lp = f"{self.lp}extract:"
        if data_len == 0:
            logger.debug(f"{lp} No data to parse AT BEGINNING OF FUNCTION!!!!!!!")
        else:
            raw_data = bytes(data)
            cache_data = CacheData()
            cache_data.timestamp = time.time()
            cache_data.all_data = raw_data

            if self.needs_more_data is True:
                logger.debug(
                    f"{lp} It seems we have a partial packet (needs_more_data), need to append to "
                    f"previous remaining data and re-parse..."
                )
                old_cdata: CacheData = self.read_cache[-1]
                if old_cdata:
                    data = old_cdata.data + data
                    cache_data.raw_data = bytes(data)
                    # Previous data [length: 16, need: 42] // Current data [length: 530] //
                    #   New (current + old) data [length: 546] // reconstructed: False
                    logger.debug(
                        f"{lp} Previous data [length: {old_cdata.data_len}, need: "
                        f"{old_cdata.needed_len}] // Current data [length: {data_len}] // "
                        f"New (current + old) data [length: {len(data)}] // reconstructed: {data_len+old_cdata.data_len == len(data)}"
                    )

                    (
                        logger.debug(f"DBG>>>{lp}NEW DATA:\n{data}\n")
                        if CYNC_RAW is True
                        else None
                    )
                else:
                    raise RuntimeError(f"{lp} No previous cache data to extract from!")
                self.needs_more_data = False
            i = 0
            while True:
                i += 1
                lp = f"{self.lp}extract:loop {i}:"
                if not data:
                    # logger.debug(f"{lp} No more data to parse!")
                    break
                data_len = len(data)
                needed_length = data_len
                if data[0] in ALL_HEADERS:
                    if data_len > 4:
                        packet_length = data[4]
                        pkt_len_multiplier = data[3]
                        needed_length = ((pkt_len_multiplier * 256) + packet_length) + 5
                    else:
                        logger.debug(
                            f"DBG>>>{lp} Packet length is less than 4 bytes, setting needed_length to data_len"
                        )
                else:
                    logger.warning(
                        f"{lp} Unknown packet header: {data[0].to_bytes(1, 'big').hex(' ')}"
                    )

                if needed_length > data_len:
                    self.needs_more_data = True
                    logger.warning(
                        f"{lp} Extracted packet length is longer than remaining data length! "
                        f"need: {needed_length} // have: {data_len}, storing data for next read!"
                    )
                    cache_data.needed_len = needed_length
                    cache_data.data_len = data_len
                    cache_data.data = bytes(data)
                    (
                        logger.debug(f"{lp} cache_data: {cache_data}")
                        if CYNC_RAW is True
                        else None
                    )
                    data = data[needed_length:]
                    continue

                extracted_packet = data[:needed_length]
                # cut data down
                data = data[needed_length:]
                await self.parse_packet(extracted_packet)

                if data:
                    (
                        logger.debug(f"{lp} Remaining data to parse: {len(data)} bytes")
                        if CYNC_RAW is True
                        else None
                    )

            self.read_cache.append(cache_data)
            limit = 20
            if len(self.read_cache) > limit:
                # keep half of limit packets
                limit = limit // -2
                self.read_cache = self.read_cache[limit:]
            if CYNC_RAW is True:
                logger.debug(
                    f"{lp} END OF RAW READING of {len(raw_data)} bytes\n"
                    f"BYTES: {raw_data}\n"
                    f"HEX: {raw_data.hex(' ')}\n"
                    f"INT: {bytes2list(raw_data)}\n\n"
                )

    async def parse_packet(self, data: bytes):
        """Parse what type of packet based on header (first 4 bytes)"""

        lp = f"{self.lp}parse:x{data[0]:02x}:"
        packet_data: Optional[bytes] = None
        pkt_header_len = 12
        packet_header = data[:pkt_header_len]
        # logger.debug(f"{lp} Parsing packet header: {packet_header.hex(' ')}") if CYNC_RAW is True else None
        # byte 1 (2, 3 are unknown)
        # pkt_type = int(packet_header[0]).to_bytes(1, "big")
        pkt_type = packet_header[0]
        # byte 4, packet length factor. each value is multiplied by 256 and added to the next byte for packet payload length
        pkt_multiplier = packet_header[3] * 256
        # byte 5
        packet_length = packet_header[4] + pkt_multiplier
        # byte 6-10, unknown but seems to be an identifier that is handed out by the device during handshake
        queue_id = packet_header[5:10]
        # byte 10-12, unknown but seems to be an additional identifier that gets incremented.
        msg_id = packet_header[9:12]
        # check if any data after header
        if len(data) > pkt_header_len:
            packet_data = data[pkt_header_len:]
        else:
            # logger.warning(f"{lp} there is no data after the packet header: [{data.hex(' ')}]")
            pass
        # logger.debug(f"{lp} raw data length: {len(data)} // {data.hex(' ')}")
        # logger.debug(f"{lp} packet_data length: {len(packet_data)} // {packet_data.hex(' ')}")
        if pkt_type in DEVICE_STRUCTS.requests:
            if pkt_type == 0x23:
                queue_id = data[6:10]
                _dbg_msg = (f"\nRAW HEX: {data.hex(' ')}\nRAW INT: "
                            f"{str(bytes2list(data)).lstrip('[').rstrip(']').replace(',','')}"
                            ) if CYNC_RAW is True else ''
                logger.debug(
                    f"{lp} Device IDENTIFICATION KEY EXCHANGE packet with ID: '{queue_id.hex(' ')}'{_dbg_msg}"
                )
                self.queue_id = queue_id
                await self.write(bytes(DEVICE_STRUCTS.responses.auth_ack))
                # MUST SEND a3 before you can ask device for anything over HTTP
                # Device sends msg identifier (aka: key), server acks that we have the key and store for future comms.
                await asyncio.sleep(0.5)
                await self.send_a3(queue_id)
            # device wants to connect before accepting commands
            elif pkt_type == 0xC3:
                conn_time_str = ""
                ack_c3 = bytes(DEVICE_STRUCTS.responses.connection_ack)
                if self.last_xc3_request is not None:
                    elapsed = time.time() - self.last_xc3_request
                    conn_time_str = f" // Last request was {elapsed:.2f} seconds ago"
                logger.debug(
                    f"{lp} CONNECTION REQUEST, replying with: {ack_c3.hex(' ')}{conn_time_str}"
                )
                self.last_xc3_request = time.time()
                await self.write(ack_c3)
            # Ping/Pong
            elif pkt_type == 0xD3:
                ack_d3 = bytes(DEVICE_STRUCTS.responses.ping_ack)
                # logger.debug(f"{lp} Client sent HEARTBEAT, replying with {ack_d3.hex(' ')}")
                await self.write(ack_d3)
            elif pkt_type == 0xA3:
                logger.debug(f"{lp} APP ANNOUNCEMENT packet: {packet_data.hex(' ')}")
                ack = DEVICE_STRUCTS.xab_generate_ack(queue_id, bytes(msg_id))
                logger.debug(f"{lp} Sending ACK -> {ack.hex(' ')}")
                await self.write(ack)
            elif pkt_type == 0xAB:
                # We sent a 0xa3 packet, device is responding with 0xab. msg contains ascii 'xlink_dev'.
                # sometimes this is sent with other data. there may be remaining data to read in the enxt raw msg.
                # http msg buffer seems to be 1024 bytes.
                # 0xab packets are 1024 bytes long, so if any data is prepended, the remaining 0xab data will be in the next raw read
                pass
            elif pkt_type == 0x7B:
                # device is acking one of our x73 requests
                pass
            elif pkt_type == 0x43:
                if packet_data:
                    if packet_data[:2] == bytes([0xC7, 0x90]):
                        # [c7 90]
                        # There is some sort of timestamp in the packet, not status
                        # 0x2c = ',' // 0x3a = ':'
                        # iterate packet_data for the : and ,
                        # first there will be year/month/day : hourminute :- ?? , ????? , new , ????? , ????? , ????? ,

                        # full color light strip 3.0.204 has different offsets (packet_data len = 51, 6 bytes more than 1.x.yyy)
                        # has additional 2 bytes at end and in the middle of timestamp there is a new 3 digit entry with a comma (4 bytes + 2 = 6 bytes, which is what were over the old style)
                        # "c7 90 2e 32 30 32 34 30 33 31 30 3a 31 31 31 30 3a 2d 35 39 2c 30 30 31 35 31 2c 30 30 32 2c 30 30 30 30 30 2c 30 30 30 30 30 2c 30 30 30 30 30 2c 43 db"
                        # packet_data = 51
                        # 32 30 32 34 30 33 31 30 3a 31 31 31 30 3a 2d 35 39 2c 30 30 31 35
                        # 20240310:1110:-59,00151,002,00000,00000,00000, 46 bytes long + 3 byte prefix + 2 byte suffix

                        # OLD can just read until end of packet_data
                        # "c7 90 2a 32 30 32 34 30 39 30 31 3a 31 38 35 39 3a 2d 34 32 2c 30 32 33 32 32 2c 30 30 30 30 34 2c 30 30 31 30 33 2c 30 30 30 36 33 2c" OLD
                        # "c7 90 2e 32 30 32 34 30 33 31 30 3a 31 31 31 30 3a 2d 35 39 2c 30 30 31 35 31 2c 30 30 32 2c 30 30 30 30 30 2c 30 30 30 30 30 2c 30 30 30 30 30 2c 43 db" NEW
                        # is 0x2C the end of ts?

                        # [199, 144, 42, 50, 48, 50, 52, 48, 57, 48, 49, 58, 49, 56, 53, 57, 58, 45, 52, 50, 44, 48, 50, 51, 50, 50, 44, 48, 48, 48, 48, 52, 44, 48, 48, 49, 48, 51, 44, 48, 48, 48, 54, 51, 44]

                        # 32 30 32 34 30 39 30 31 3a 31 38 35 39 3a 2d 34 32 2c 30 32 33 32 32 2c 30 30 30 30 34 2c 30 30 31 30 33 2c 30 30 30 36 33
                        # 20240901:1859:-42,02322,00004,00103,00063,
                        # packet_data = 45

                        ts_idx = 3
                        ts_end_idx = -1
                        ts: Optional[bytes] = None
                        # logger.debug(
                        #     f"{lp} Device TIMESTAMP PACKET ({len(bytes.fromhex(packet_data.hex()))}) -> HEX: "
                        #     f"{packet_data.hex(' ')} // INTS: {bytes2list(packet_data)} // "
                        #     f"ASCII: {packet_data.decode(errors='replace')}"
                        # ) if CYNC_RAW is True else None
                        # setting version from config file wouldnt be reliable if the user doesnt bump the version
                        # when updating cync firmware. we can only rely on the version sent by the device.
                        # there is no guarantee the version is sent before checking the timestamp, so use a gross hack.
                        if self.version and (self.version >= 30000 <= 40000):
                            ts_end_idx = -2

                        ts = packet_data[ts_idx:ts_end_idx]
                        if ts:
                            ts_ascii = ts.decode("ascii", errors="replace")
                            # gross hack
                            if ts_ascii[-1] != ",":
                                if not ts_ascii[-1].isdigit():
                                    ts_ascii = ts_ascii[:-1]
                            logger.debug(
                                f"{lp} Device sent TIMESTAMP -> {ts_ascii} - replying..."
                            )
                            self.device_timestamp = ts_ascii
                        else:
                            logger.debug(
                                f"{lp} Could not decode timestamp from: {packet_data.hex(' ')}"
                            )
                    else:
                        # 43 00 00 00 2d 39 87 c8 57 01 01 06| [(06 00 10) {03  C...-9..W.......
                        # 01 64 32 00 00 00 01} ff 07 00 00 00 00 00 00] 07  .d2.............
                        # 00 10 02 01 64 32 00 00 00 01 ff 07 00 00 00 00  ....d2..........
                        # 00 00
                        # status struct is 19 bytes long
                        struct_len = 19
                        extractions = []
                        try:
                            # logger.debug(
                            #     f"{lp} Device sent BROADCAST STATUS packet => '{packet_data.hex(' ')}'"
                            # )if CYNC_RAW is True else None
                            for i in range(0, packet_length, struct_len):
                                extracted = packet_data[i : i + struct_len]
                                if extracted:
                                    status_struct = extracted[3:11]
                                    # 14 00 10 01 00 00 64 00 00 00 01 15 15 00 00 00 00 00 00
                                    # // [1, 0, 0, 100, 0, 0, 0, 1]
                                    extractions.append(
                                        (extracted.hex(" "), bytes2list(status_struct))
                                    )
                                # broadcast status data
                                # await self.write(data, broadcast=True)
                            (
                                logger.debug(
                                    "%s Extracted data and STATUS struct => %s"
                                    % (lp, extractions)
                                )
                                if CYNC_RAW is True
                                else None
                            )
                        except IndexError:
                            # The device will only send a max of 1kb of data, if the message is longer than 1kb the remainder is sent in the next read
                            logger.debug(
                                f"{lp} IndexError extracting status struct (expected)"
                            )
                        except Exception as e:
                            logger.error(f"{lp} EXCEPTION: {e}")
                # Its one of those queue id/msg id pings? 0x43 00 00 00 ww xx xx xx xx yy yy yy
                # Also notice these messages when another device gets a command
                else:
                    # logger.debug(f"{lp} received a 0x43 packet with no data, interpreting as PING, replying...")
                    pass
                ack = DEVICE_STRUCTS.x48_generate_ack(bytes(msg_id))
                # logger.debug(f"{lp} Sending ACK -> {ack.hex(' ')}") if CYNC_RAW is True else None
                await self.write(ack)
                (
                    logger.debug(f"DBG>>>{lp} RAW DATA: {len(data)} BYTES")
                    if CYNC_RAW is True
                    else None
                )
            elif pkt_type == 0x83:
                # When the device sends a packet starting with 0x83, data is wrapped in 0x7e.
                # firmware version is sent without 0x7e boundaries
                if packet_data is not None:
                    # logger.debug(f"{lp} Extracted BOUND data ({len(bytes(packet_data))} bytes) => {packet_data.hex(' ')}")

                    # 0x83 inner struct - not always bound by 0x7e (firmware response doesn't have starting boundary, has ending boundary 0x7e)
                    # firmware info, data len = 30 (0x32), fw starts idx 23-27, 20-22 fw type (86 01 0x)
                    #  {83 00 00 00 32} {[39 87 c8 57] [00 03 00]} {00 00 00 00  ....29..W.......
                    #  00 fa 00 20 00 00 00 00 00 00 00 00 ea 00 00 00  ... ............
                    #  86 01 01 31[idx=23 packet_data] 30 33 36 31 00 00 00 00 00 00 00 00  ...10361........
                    #  00 00 00 00 00 [8d] [7e]}                             ......~
                    # firmware packet may only be sent on startup / network reconnection

                    if packet_data[0] == 0x00:
                        fw_type, fw_ver, fw_str = parse_unbound_firmware_version(
                            packet_data, lp
                        )
                        if fw_type == "device":
                            self.version = fw_ver
                            self.version_str = fw_str
                        else:
                            self.network_version = fw_ver
                            self.network_version_str = fw_str

                    elif packet_data[0] == DATA_BOUNDARY:
                        # device internal status. state can be off and brightness set to a non 0.
                        # signifies what brightness when state = on, meaning don't rely on brightness for on/off.

                        # 83 00 00 00 25 37 96 24 69 00 05 00 7e {21 00 00
                        #  00} {[fa db] 13} 00 (34 22) 11 05 00 [05] 00 db
                        #  11 02 01 [00 64 00 00 00 00] 00 00 b3 7e

                        # checksum is 2nd last byte, last byte is 0x7e
                        checksum = packet_data[-2]
                        inner_header = packet_data[1:6]
                        ctrl_bytes = packet_data[5:7]
                        # removes checksum byte and 0x7e
                        inner_data = packet_data[6:-2]
                        calc_chksum = sum(inner_data) % 256

                        # This has the HTTP devices internal status of all devices in BTLE mesh.
                        # This data can be wrong! sometimes reports wrong state and the RGB colors are slightly different from each device.
                        # todo: need to not parse this data if we just issued a command or we do like mesh info and create a voting system
                        if ctrl_bytes == bytes([0xFA, 0xDB]):
                            add_one = False
                            if len(inner_data) == 22:
                                pass
                            elif len(inner_data) == 23:
                                add_one = True
                                logger.debug(
                                    f"{lp} Adding one to index for packet data as "
                                    f"inner_data length = 23 and revising checksum calculation"
                                )
                            else:
                                logger.warning(
                                    f"{lp} Unknown packet INNER data length: {len(inner_data)}"
                                )
                            if add_one is False:
                                calc_chksum = sum(inner_data) % 256
                            else:
                                chksum_inner_data = list(inner_data)
                                chksum_inner_data.pop(4)
                                calc_chksum = sum(chksum_inner_data) % 256
                            # logger.debug(f"DBG>>> {bytes2list(packet_data[9:12]) = } // {bytes2list(packet_data[9:12]) == [17, 17, 17] = }")

                            # LED controller has this pattern
                            if bytes2list(packet_data[9:12]) == [17, 17, 17]:
                                # LED controller sends its internal state in a stream
                                # Only the first packet in the stream has the correct checksum.
                                # All following 0x83 internal status packets for this stream will have the same checksum as the first packet.
                                # As soon as we get an internal status without the first packets calculated checksum, we know that series is
                                # done sending and it will just send regular status packets, my guess is this is a bug or an identifier that
                                # the packet belongs to the stream
                                if self.first_83_packet_checksum is None:
                                    # we want to calc the checksum and store it to compare to other packets in the series

                                    self.first_83_packet_checksum = checksum
                                    if calc_chksum != checksum:
                                        logger.warning(
                                            f"{lp} Checksum mismatch in INITIAL STATUS STREAM - FIRST packet data, "
                                            f"calculated: {calc_chksum} // received: {checksum}"
                                        )

                                else:
                                    if checksum == self.first_83_packet_checksum:
                                        logger.debug(
                                            f"{lp} INITIAL STATUS STREAM packet data (override "
                                            f"calculated checksum), old: {calc_chksum} // checksum: "
                                            f"{checksum} // saved: {self.first_83_packet_checksum}"
                                        )
                                        calc_chksum = self.first_83_packet_checksum
                                    else:
                                        self.first_83_packet_checksum = None

                            if calc_chksum != checksum:
                                logger.warning(
                                    f"{lp} Checksum mismatch in packet data, calculated: {calc_chksum} // received: {checksum}"
                                )

                            id_idx = 14 if add_one is False else 15
                            connected_idx = 19 if add_one is False else 20
                            state_idx = 20 if add_one is False else 21
                            bri_idx = 21 if add_one is False else 22
                            tmp_idx = 22 if add_one is False else 23
                            r_idx = 23 if add_one is False else 24
                            g_idx = 24 if add_one is False else 25
                            b_idx = 25 if add_one is False else 26
                            dev_id = packet_data[id_idx]
                            state = packet_data[state_idx]
                            bri = packet_data[bri_idx]
                            tmp = packet_data[tmp_idx]
                            _red = packet_data[r_idx]
                            _green = packet_data[g_idx]
                            _blue = packet_data[b_idx]
                            connected_to_mesh = packet_data[connected_idx]
                            raw_status: bytes = bytes(
                                [
                                    dev_id,
                                    state,
                                    bri,
                                    tmp,
                                    _red,
                                    _green,
                                    _blue,
                                    connected_to_mesh,
                                ]
                            )
                            ___dev = g.server.devices.get(dev_id)
                            if ___dev:
                                dev_name = f'"{___dev.name}" (ID: {dev_id})'
                            else:
                                dev_name = f"Device ID: {dev_id}"
                            pktdata_int = [
                                str(x) for x in bytes2list(packet_data[1:-1])
                            ]
                            # pktdata_int = ['00' if part == '0' else part for part in [str(x) for x in bytes2list(packet_data[1:-1])]]
                            pkthdr_int = [str(x) for x in bytes2list(packet_header)]
                            _dbg_msg = (f"\n\n"
                                        f"RAW HEX: {packet_data[1:-1].hex(' ')}\nRAW INT: "
                                        f"{' '.join(pktdata_int)}\nPACKET HEADER: {packet_header.hex(' ')} "
                                        f"// {' '.join(pkthdr_int)}"
                                        ) if CYNC_RAW is True else ''
                            logger.debug(
                                f"{lp} Internal STATUS for {dev_name} = {bytes2list(raw_status)}{_dbg_msg}"

                            )
                            await g.server.parse_status(raw_status)
                        else:
                            if ctrl_bytes == bytes([0xFA, 0xAF]):
                                logger.debug(
                                    f"{lp} This ctrl struct ({ctrl_bytes.hex(' ')} // checksum valid: "
                                    f"{checksum == calc_chksum}) usually comes through "
                                    f"when the cync phone app connects to the BTLE mesh. Unknown what it means, "
                                    f"the only variable data is bytes 8-11 and the checksum at the end.\n\n"
                                    f"HEX: {packet_data[1:-1].hex(' ')}\nINT: {bytes2list(packet_data[1:-1])}"
                                )
                            elif ctrl_bytes == bytes([0xFA, 0xD9]):
                                logger.debug(
                                    f"{lp} Seen this ctrl struct ({ctrl_bytes.hex(' ')} // checksum valid: "
                                    f"{checksum == calc_chksum}), unknown what it means.\n\n"
                                    f"HEX: {packet_data[1:-1].hex(' ')}\nINT: {bytes2list(packet_data[1:-1])}"
                                )
                            else:
                                logger.warning(
                                    f"{lp} UNKNOWN packet data (ctrl_bytes: {ctrl_bytes.hex(' ')} // "
                                    f"msg_id: {inner_header.hex(' ')} // checksum valid: "
                                    f"{checksum == calc_chksum})\n\n"
                                    f"HEX: {packet_data[1:-1].hex(' ')}\n"
                                    f"INT: {bytes2list(packet_data[1:-1])}"
                                )

                else:
                    logger.warning(
                        f"{lp} packet with no data????? After stripping header, queue and "
                        f"msg id, there is no data to process?????"
                    )
                ack = DEVICE_STRUCTS.x88_generate_ack(msg_id)
                # logger.debug(f"{lp} RAW DATA: {data.hex(' ')}")
                # logger.debug(f"{lp} Sending ACK -> {ack.hex(' ')}")
                await self.write(ack)

            elif pkt_type == 0x73:
                # logger.debug(f"{lp} Control packet received: {packet_data.hex(' ')}") if CYNC_RAW is True else None
                if packet_data is not None:

                    # 0x73 should ALWAYS have 0x7e bound data.
                    # check for boundary, all bytes between boundaries are for this request
                    if packet_data[0] == DATA_BOUNDARY:
                        # checksum is 2nd last byte, last byte is 0x7e
                        checksum = packet_data[-2]
                        inner_header = packet_data[1:6]
                        ctrl_bytes = packet_data[5:7]
                        # removes checksum byte and 0x7e
                        inner_data = packet_data[6:-2]
                        calc_chksum = sum(inner_data) % 256

                        # find next 0x7e and extract the inner struct
                        end_bndry_idx = packet_data[1:].find(DATA_BOUNDARY) + 1
                        inner_struct = packet_data[1:end_bndry_idx]
                        inner_struct_len = len(inner_struct)
                        # ctrl bytes 0xf9, 0x52 indicates this is a mesh info struct
                        # some device firmwares respond with a message received packet before replying with the data
                        # example: 7e 1f 00 00 00 f9 52 01 00 00 53 7e (12 bytes, 0x7e bound. 10 bytes of data)
                        if ctrl_bytes == bytes([0xF9, 0x52]):
                            # logger.debug(f"{lp} got a mesh info response (len: {inner_struct_len}): {inner_struct.hex(' ')}")
                            if inner_struct_len < 15:
                                if inner_struct_len == 10:
                                    # server sent mesh info request, this seems to be the ack?
                                    # 7e 1f 00 00 00 f9 52 01 00 00 53 7e
                                    # checksum (idx 10) = idx 6 + idx 7 % 256
                                    # seen this with Full Color LED light strip controller firmware version: 3.0.204
                                    succ_idx = 6
                                    minfo_ack_succ = inner_struct[succ_idx]
                                    minfo_ack_chksum = inner_struct[9]
                                    calc_chksum = (
                                        inner_struct[5] + inner_struct[6]
                                    ) % 256
                                    if minfo_ack_succ == 0x01:
                                        # logger.debug(f"{lp} Mesh info request ACK received, success: {minfo_ack_succ}."
                                        #              f" checksum byte = {minfo_ack_chksum}) // Calculated checksum "
                                        #              f"= {calc_chksum}")
                                        if minfo_ack_chksum != calc_chksum:
                                            logger.warning(
                                                f"{lp} Mesh info request ACK checksum failed! {minfo_ack_chksum} != {calc_chksum}"
                                            )
                                    else:
                                        logger.warning(
                                            f"{lp} Mesh info request ACK failed! success byte: {minfo_ack_succ}"
                                        )

                                else:
                                    logger.debug(
                                        f"{lp} inner_struct is less than 15 bytes: {inner_struct.hex(' ')}"
                                    )
                            else:
                                # 15th OR 16th byte of inner struct is start of mesh info, 24 bytes long
                                minfo_start_idx = 14
                                minfo_length = 24
                                if inner_struct[minfo_start_idx] == 0x00:
                                    minfo_start_idx += 1
                                    logger.warning(
                                        f"{lp}mesh: dev_id is 0 when using index: {minfo_start_idx-1}, "
                                        f"trying index {minfo_start_idx} = {inner_struct[minfo_start_idx]}"
                                    )

                                if inner_struct[minfo_start_idx] == 0x00:
                                    logger.error(
                                        f"{lp}mesh: dev_id is 0 when using index: {minfo_start_idx}, skipping..."
                                    )
                                else:
                                    # from what I've seen, the mesh info is 24 bytes long and repeats until the end.
                                    # Reset known device ids, mesh is the final authority on what devices are connected
                                    self.mesh_info = None
                                    self.known_device_ids = []
                                    ids_reported = []
                                    loop_num = 0
                                    mesh_info = {}
                                    _m = []
                                    _raw_m = []
                                    # structs = []
                                    try:
                                        for i in range(
                                            minfo_start_idx,
                                            inner_struct_len,
                                            minfo_length,
                                        ):
                                            loop_num += 1
                                            mesh_dev_struct = inner_struct[
                                                i : i + minfo_length
                                            ]
                                            dev_id = mesh_dev_struct[0]
                                            # logger.debug(f"{lp} inner_struct[{i}:{i + minfo_length}]={mesh_dev_struct.hex(' ')}")
                                            # parse status from mesh info
                                            #  [05 00 44   01 00 00 44   01 00     00 00 00 64  00 00 00 00   00 00 00 00 00 00 00] - plug (devices are all connected to it via BT)
                                            #  [07 00 00   01 00 00 00   01 01     00 00 00 64  00 00 00 fe   00 00 00 f8 00 00 00] - direct connect full color A19 bulb
                                            #   ID  ? type  ?  ?  ? type  ? state   ?  ?  ? bri  ?  ?  ? tmp   ?  ?  ?  R  G  B  ?
                                            type_idx = 2
                                            state_idx = 8
                                            bri_idx = 12
                                            tmp_idx = 16
                                            r_idx = 20
                                            g_idx = 21
                                            b_idx = 22
                                            dev_type_id = mesh_dev_struct[type_idx]
                                            dev_state = mesh_dev_struct[state_idx]
                                            dev_bri = mesh_dev_struct[bri_idx]
                                            dev_tmp = mesh_dev_struct[tmp_idx]
                                            dev_r = mesh_dev_struct[r_idx]
                                            dev_g = mesh_dev_struct[g_idx]
                                            dev_b = mesh_dev_struct[b_idx]
                                            # in mesh info, brightness can be > 0 when set to off
                                            # however, ive seen devices that are on have a state of 0 but brightness 100
                                            if dev_state == 0 and dev_bri > 0:
                                                dev_bri = 0
                                            raw_status = bytes(
                                                [
                                                    dev_id,
                                                    dev_state,
                                                    dev_bri,
                                                    dev_tmp,
                                                    dev_r,
                                                    dev_g,
                                                    dev_b,
                                                    1,
                                                    # dev_type,
                                                ]
                                            )
                                            _m.append(bytes2list(raw_status))
                                            _raw_m.append(mesh_dev_struct.hex(" "))
                                            if dev_id in g.cync_lan.server.devices:
                                                # first device id is the device id of the http device we are connected to
                                                ___dev = g.cync_lan.server.devices[dev_id]
                                                dev_name = ___dev.name
                                                if loop_num == 1:
                                                    # byte 3 (idx 2) is a device type byte but,
                                                    # it only reports on the first item (itself)
                                                    # convert to int, and it is the same as deviceType from cloud.
                                                    if not self.id:
                                                        self.id = dev_id
                                                        self.lp = f"{self.address}[{self.id}]:"
                                                        cync_device = (
                                                            g.cync_lan.cfg_devices[
                                                                dev_id
                                                            ]
                                                        )
                                                        logger.debug(
                                                            f"{self.lp}parse:x{data[0]:02x}: setting HTTP"
                                                            f"Device ID: {self.id}"
                                                        )
                                                        self.capabilities = cync_device.check_dev_capabilities(
                                                            dev_type_id
                                                        )
                                                        self.device_types = (
                                                            cync_device.check_dev_type(
                                                                dev_type_id
                                                            )
                                                        )
                                                        # logger.debug(f"{lp} device type ({dev_type_id}) capabilities: {self.capabilities}")
                                                        # logger.debug(f"{lp} device type ({dev_type_id}): {self.device_types}")
                                                    elif self.id and self.id != dev_id:
                                                        logger.warning(
                                                            f"{lp} The first device reported in 0x83 is "
                                                            f"usually the http device. current: {self.id} "
                                                            f"// proposed: {dev_id}"
                                                        )
                                                    lp = f"{self.lp}parse:x{data[0]:02x}:"
                                                    self.device_type_id = dev_type_id
                                                    self.name = dev_name

                                                ids_reported.append(dev_id)
                                                # structs.append(mesh_dev_struct.hex(" "))
                                                self.known_device_ids.append(dev_id)

                                            else:
                                                logger.warning(
                                                    f"{lp} Device ID {dev_id} not found in devices "
                                                    f"defined in config file: "
                                                    f"{g.cync_lan.server.devices.keys()}"
                                                )
                                        # -- END OF mesh info response parsing loop --
                                    except IndexError:
                                        # ran out of data
                                        # logger.debug(f"{lp} IndexError parsing mesh info response (expected)") if CYNC_RAW is True else None
                                        pass
                                    except Exception as e:
                                        logger.error(
                                            f"{lp} MESH INFO for loop EXCEPTION: {e}"
                                        )
                                    # if ids_reported:
                                    # logger.debug(
                                    #     f"{lp} from: {self.id} - MESH INFO // Device IDs reported: "
                                    #     f"{sorted(ids_reported)}"
                                    # )
                                    # if structs:
                                    #     logger.debug(
                                    #         f"{lp} from: {self.id} -  MESH INFO // STRUCTS: {structs}"
                                    #     )
                                    if self.parse_mesh_status is True:
                                        logger.debug(
                                            f"{lp} parse_mesh_status is TRUE, parsing mesh info // {_m} // {_raw_m}"
                                        )
                                        for status in _m:
                                            await g.server.parse_status(bytes(status))

                                    mesh_info["status"] = _m
                                    mesh_info["id_from"] = self.id
                                    # logger.debug(f"\n\n{lp} MESH INFO // {_raw_m}\n")
                                    self.mesh_info = MeshInfo(**mesh_info)
                                    # Send mesh status ack
                                    # 73 00 00 00 14 2d e4 b5 d2 15 2d 00 7e 1e 00 00
                                    #  00 f8 {af 02 00 af 01} 61 7e
                                    # checksum 61 hex = int 97 solved: {af+02+00+af+01} % 256 = 97
                                    mesh_ack = bytes([0x73, 0x00, 0x00, 0x00, 0x14])
                                    mesh_ack += bytes(self.queue_id)
                                    mesh_ack += bytes([0x00, 0x00, 0x00])
                                    mesh_ack += bytes(
                                        [
                                            0x7E,
                                            0x1E,
                                            0x00,
                                            0x00,
                                            0x00,
                                            0xF8,
                                            0xAF,
                                            0x02,
                                            0x00,
                                            0xAF,
                                            0x01,
                                            0x61,
                                            0x7E,
                                        ]
                                    )
                                    # logger.debug(f"{lp} Sending MESH INFO ACK -> {mesh_ack.hex(' ')}")
                                    await self.write(mesh_ack)
                                    # Always clear parse mesh status
                                    self.parse_mesh_status = False
                        else:
                            (
                                logger.debug(
                                    f"{lp} control bytes (checksum: {checksum}, verified: {checksum == calc_chksum}): {ctrl_bytes.hex(' ')} // packet data:  {packet_data.hex(' ')}"
                                )
                                if CYNC_RAW
                                else None
                            )

                            if ctrl_bytes[0] == 0xF9 and ctrl_bytes[1] in (0xD0, 0xF0):
                                # control packet ack - changed state.
                                # handle callbacks for messages
                                # byte 8 is success? 0x01 yes // 0x00 no
                                # 7e 09 00 00 00 f9 d0 01 00 00 d1 7e
                                # 7e 09 00 00 00 f9 f0 01 00 00 f1 7e <-- newer LED strip controller
                                # byte 7 (f0) + 8 (01) = checksum (f1)
                                # logger.debug(f"{lp} CONTROL packet ACK (ctrl_bytes = {ctrl_bytes.hex(' ')}) "
                                #              f"(extracted data = {packet_data.hex(' ')}) -> success: {packet_data[7]}")
                                pass
                            # newer firmware devices seen in led light strip so far,
                            # send their firmware version data in a 0x7e bound struct.
                            # I've also seen these ctrl bytes in the msg that other devices send in FA AF
                            # the struct is 31 bytes long with the 0x7e boundaries, unbound it is 29 bytes long
                            elif ctrl_bytes == bytes([0xFA, 0x8E]):
                                if packet_data[1] == 0x00:
                                    logger.debug(
                                        f"{lp} Device sent ({ctrl_bytes.hex(' ')}) BOUND firmware version data"
                                    )
                                    fw_type, fw_ver, fw_str = (
                                        parse_unbound_firmware_version(
                                            packet_data[1:-1], lp
                                        )
                                    )
                                    if fw_type == "device":
                                        self.version = fw_ver
                                        self.version_str = fw_str
                                    else:
                                        self.network_version = fw_ver
                                        self.network_version_str = fw_str
                                else:
                                    logger.debug(
                                        f"{lp} This ctrl struct ({ctrl_bytes.hex(' ')} // checksum valid: {checksum == calc_chksum}) usually comes through "
                                        f"when the cync phone app connects to the BTLE mesh. Unknown what it means, "
                                        f"the only variable data is bytes 8-11 and the checksum at the end before "
                                        f"the closing boundary 0x7e.\n\nHEX: {packet_data[1:-1].hex(' ')}\nINT: {bytes2list(packet_data[1:-1])}"
                                    )

                            else:
                                logger.debug(
                                    f"{lp} UNKNOWN CTRL_BYTES: {ctrl_bytes.hex(' ')} // EXTRACTED DATA -> "
                                    f"{packet_data.hex(' ')}"
                                )
                    else:
                        logger.debug(
                            f"{lp} packet with no boundary found????? After stripping header, queue and "
                            f"msg id, there is no data to process?????"
                        )

                    ack = DEVICE_STRUCTS.x7b_generate_ack(queue_id, msg_id)
                    # logger.debug(f"{lp} Sending ACK -> {ack.hex(' ')}")
                    await self.write(ack)
                else:
                    logger.warning(
                        f"{lp} packet with no data????? After stripping 12 bytes header (5), queue (4) and "
                        f"msg id (3), there is no data to process!?!"
                    )

        # unknown data we don't know the header for
        else:
            logger.debug(
                f"{lp} sent UNKNOWN HEADER! Don't know how to respond!{RAW_MSG}"
            )

    async def ask_for_mesh_info(self, parse: bool = False):
        """
        Ask the device for mesh info. As far as I can tell, this will return whatever
        devices are connected to the device you are querying. It may also trigger
        the device to send its own status packet.
        """
        lp = self.lp
        # mesh_info = '73 00 00 00 18 2d e4 b5 d2 15 2c 00 7e 1f 00 00 00 f8 52 06 00 00 00 ff ff 00 00 56 7e'
        mesh_info_data = bytes(list(DEVICE_STRUCTS.requests.x73))
        # last byte is data len multiplier (multiply value by 256 if data len > 256)
        mesh_info_data += bytes([0x00, 0x00, 0x00])
        # data len
        mesh_info_data += bytes([0x18])
        # Queue ID
        mesh_info_data += self.queue_id
        # Msg ID, I tried other variations but that results in: no 0x83 and 0x43 replies from device.
        # 0x00 0x00 0x00 seems to work
        mesh_info_data += bytes([0x00, 0x00, 0x00])
        # Bound data (0x7e)
        mesh_info_data += bytes(
            [
                0x7E,
                0x1F,
                0x00,
                0x00,
                0x00,
                0xF8,
                0x52,
                0x06,
                0x00,
                0x00,
                0x00,
                0xFF,
                0xFF,
                0x00,
                0x00,
                0x56,
                0x7E,
            ]
        )
        # logger.debug(f"{lp} Asking device for BT mesh info:\nBYTES: {mesh_info_data}\nHEX: {mesh_info_data.hex(' ')}\n"
        #              f"INT: {bytes2list(mesh_info_data)}") if CYNC_RAW is True else None
        try:
            if parse is True:
                self.parse_mesh_status = True
            await self.write(mesh_info_data)
        except TimeoutError as to_exc:
            logger.error(f"{lp} asking for mesh info timed out, likely powered off")
            raise to_exc
        except Exception as e:
            logger.error(f"{lp} EXCEPTION: {e}", exc_info=True)

    async def send_a3(self, q_id: bytes):
        a3_packet = bytes([0xA3, 0x00, 0x00, 0x00, 0x07])
        a3_packet += q_id
        # random 2 bytes
        rand_bytes = self.xa3_msg_id = random.getrandbits(16).to_bytes(2, "big")
        rand_bytes += bytes([0x00])
        self.xa3_msg_id += random.getrandbits(8).to_bytes(1, "big")
        a3_packet += rand_bytes
        logger.debug(
            f"{self.lp} Sending 0xa3 (want to control) packet -> {a3_packet.hex(' ')}"
        )
        await self.write(a3_packet)
        self.ready_to_control = True

    async def receive_task(self):
        """
        Receive data from the device and respond to it. This is the main task for the device.
        It will respond to the device and handle the messages it sends.
        Runs in an infinite loop.
        """
        lp = f"{self.address}:raw read:"
        started_at = time.time()
        name = self.tasks.receive.get_name()
        logger.debug(f"{lp} receive_task CALLED") if CYNC_RAW is True else None
        try:
            while True:
                try:
                    data: bytes = await self.read()
                    if data is False:
                        logger.debug(
                            f"{lp} read() returned False, exiting {name} "
                            f"(started at: {datetime.datetime.fromtimestamp(started_at)})..."
                        )
                        break
                    if not data:
                        await asyncio.sleep(0)
                        continue
                    await self.parse_raw_data(data)

                except Exception as e:
                    logger.error(f"{lp} Exception in {name} LOOP: {e}", exc_info=True)
                    break
        except asyncio.CancelledError as cancel_exc:
            logger.debug(f"%s %s CANCELLED: %s" % (lp, name, cancel_exc))

        logger.debug(f"{lp} {name} FINISHED")

    async def read(self, chunk: Optional[int] = None):
        """Read data from the device if there is an open connection"""
        lp = f"{self.lp}read:"
        if self.closing is True:
            logger.debug(f"{lp} closing is True, exiting read()...")
            return False
        else:
            if chunk is None:
                chunk = CYNC_CHUNK_SIZE
            async with self.read_lock:
                if self.reader:
                    if not self.reader.at_eof():
                        try:
                            raw_data = await self.reader.read(chunk)
                        except Exception as read_exc:
                            logger.error(f"{lp} Base EXCEPTION: {read_exc}")
                            return False
                        else:
                            return raw_data
                    else:
                        logger.debug(
                            f"{lp} reader is at EOF, setting read socket to None..."
                        )
                        self.reader = None
                else:
                    logger.debug(
                        f"{lp} reader is None/empty -> {self.reader = } // TYPE: {type(self.reader)}"
                    )
                    return False

    async def write(self, data: bytes, broadcast: bool = False) -> Optional[bool]:
        """
        Write data to the device if there is an open connection

        :param data: The raw binary data to write to the device
        :param broadcast: If True, write to all HTTP devices connected to the server
        """
        if not isinstance(data, bytes):
            raise ValueError(f"Data must be bytes, not type: {type(data)}")
        dev = self
        if dev.closing:
            logger.warning(f"{dev.lp} device is closing, not writing data")
        else:
            if dev.writer is not None:
                async with dev.write_lock:
                    # if broadcast is True:inner_struct__
                    #     # replace queue id with the sending device's queue id
                    #     new_data = bytes2list(data)
                    #     new_data[5:9] = dev.queue_id
                    #     data = bytes(new_data)

                    # check if the underlying writer is closing
                    if dev.writer.is_closing():
                        if dev.closing is False:
                            # this is probably a connection that was closed by the device (turned off), delete it
                            logger.warning(
                                f"{dev.lp} underlying writer is closing but, "
                                f"the device itself hasn't called close(). The device probably "
                                f"dropped the connection (lost power). Removing {dev.address}"
                            )
                            off_dev = g.server.http_devices.pop(dev.address, None)
                            del off_dev

                        else:
                            logger.debug(
                                f"{dev.lp} HTTP device is closing, not writing data... "
                            )
                    else:
                        dev.writer.write(data)
                        # logger.debug(f"{dev.lp} writing data -> {data}")
                        try:
                            await asyncio.wait_for(dev.writer.drain(), timeout=2.0)
                        except TimeoutError as to_exc:
                            logger.error(
                                f"{dev.lp} writing data to the device timed out, likely powered off"
                            )
                            raise to_exc
                        else:
                            return True
            else:
                logger.warning(f"{dev.lp} writer is None, can't write data!")
            return None

    async def delete(self):
        """Remove self from cync devices and delete all references"""
        lp = f"{self.lp}delete:"
        try:
            logger.debug(
                f"{lp} Removing device ID: {self.id} ({self.address}) - marking MQTT offline first..."
            )
            if self.id in g.server.devices:
                dev = g.server.devices[self.id]
                dev.online = False
                logger.debug(f"{lp} Device ID: {self.id} - set offline...")
            logger.debug(f"{lp} Cancelling device tasks...")
            try:
                self.tasks.receive.cancel()
                _ = self.tasks.receive.result()
            except Exception as e:
                logger.error(f"{lp} EXCEPTION: {e}", exc_info=True)

            # SShouldn't need to do this, the streams are dead anyway.
            logger.debug(f"{lp} Closing device streams...")
            await self.close()

        except Exception as e:
            logger.error(f"{lp} EXCEPTION: {e}", exc_info=True)
        else:
            logger.info(f"{lp} Device {self.address} ready for deletion")
            return self

    async def close(self):
        logger.debug(f"{self.lp} close() called")
        self.closing = True
        try:
            if self.writer:
                async with self.write_lock:
                    self.writer.close()
                    await self.writer.wait_closed()
        except Exception as e:
            logger.error(f"{self.address}:close:writer: EXCEPTION: {e}", exc_info=True)
        finally:
            self.writer = None

        try:
            if self.reader:
                async with self.read_lock:
                    self.reader.feed_eof()
                    await asyncio.sleep(0.01)
        except Exception as e:
            logger.error(f"{self.address}:close:reader: EXCEPTION: {e}", exc_info=True)
        finally:
            self.reader = None

        self.closing = False

    @property
    def reader(self):
        return self._reader

    @reader.setter
    def reader(self, value: asyncio.StreamReader):
        self._reader = value

    @property
    def writer(self):
        return self._writer

    @writer.setter
    def writer(self, value: asyncio.StreamWriter):
        self._writer = value


# Most of the mqtt code came from cync2mqtt


class MQTTClient:
    # from cync2mqtt

    lp: str = "mqtt:"

    availability = False

    async def pub_online(self, device_id: int, status: bool):
        lp = f"{self.lp}pub_online:"
        if device_id not in g.server.devices:
            logger.error(
                f"{lp} Device ID {device_id} not found?! Have you deleted or added any devices recently? "
                f"You may need to re-export devices from your Cync account!"
            )
            return
        availability = b"online" if status else b"offline"
        device: CyncDevice = g.server.devices[device_id]
        device_uuid = f"{device.home_id}-{device_id}"
        # logger.debug(f"{lp} Publishing availability: {availability}")
        _ = await self.client.publish(
            f"{self.topic}/availability/{device_uuid}", availability, qos=QOS_0
        )

    def __init__(
        self,
        broker_address: str,
        topic: Optional[str] = None,
        ha_topic: Optional[str] = None,
    ):
        global g

        self.shutdown_complete: bool = False
        self.tasks: Optional[List[asyncio.Task]] = None
        self.pub_queue: Optional[asyncio.Queue] = None
        self.sub_queue: Optional[asyncio.Queue] = None
        lp = f"{self.lp}init:"
        if topic is None:
            if not CYNC_TOPIC:
                topic = "cync_lan"
                logger.warning("%s MQTT topic not set, using default: %s" % (lp, topic))
            else:
                topic = CYNC_TOPIC

        if ha_topic is None:
            if not CYNC_HASS_TOPIC:
                ha_topic = "homeassistant"
                logger.warning(
                    "%s HomeAssistant topic not set, using default: %s" % (lp, ha_topic)
                )
            else:
                ha_topic = CYNC_HASS_TOPIC

        self.broker_address = broker_address
        # Negative int denotes infinite retries, from amqtt source code:
        # if reconnect_retries >= 0 and nb_attempt > reconnect_retries:
        self.client = amqtt_client.MQTTClient(
            config={
                "reconnect_retries": -1,
                "auto_reconnect": True,
                "will": {
                    "topic": f"{CYNC_TOPIC}/connected",
                    "message": DEVICE_LWT_MSG,
                    "qos": 0x01,
                    "retain": True,
                },
            }
        )
        self.topic = topic
        self.ha_topic = ha_topic

        # hardcode for now
        self.cync_mink: int = 2000
        self.cync_maxk: int = 7000
        self.cync_min_mired: int = int(1e6 / self.cync_maxk + 0.5)
        self.cync_max_mired: int = int(1e6 / self.cync_mink + 0.5)

        self.hass_minct: int = int(1e6 / 5000 + 0.5)
        self.hass_maxct: int = int(1e6 / self.cync_mink + 0.5)
        g.mqtt = self

    async def start(self):
        lp = f"{self.lp}start:"
        # loop to keep trying to connect to the broker
        max_retries = 10
        for retry in range(max_retries):
            try:
                _ = await self.client.connect(self.broker_address)
            except Exception as ce:
                logger.error(
                    "%s Connection attempt: %d failed: %s" % (lp, retry, ce),
                    exc_info=True,
                )
                try:
                    await self.client.disconnect()
                except Exception as innr_exc:
                    pass
            else:
                logger.debug("%s Connected to MQTT broker..." % lp)
                break
        else:
            logger.error(
                "%s Failed to connect to MQTT broker after %d attempts!"
                % (lp, max_retries)
            )
            raise ConnectionError(
                "Failed to connect to MQTT broker after %d attempts!" % max_retries
            )

        self.pub_queue = asyncio.Queue()
        self.sub_queue = asyncio.Queue()

        # announce to homeassistant discovery
        await self.homeassistant_discovery()
        logger.debug(f"{lp} Seeding all devices: offline")

        # seed everything offline
        for device_id, device in g.server.devices.items():
            await self.pub_online(device_id, False)

        self.tasks = [
            asyncio.create_task(self.pub_worker(self.pub_queue), name="pub_worker"),
            asyncio.create_task(self.sub_worker(self.sub_queue), name="sub_worker"),
            asyncio.create_task(self.start_subscribing(), name="data_worker"),
        ]

    async def start_subscribing(self):
        """Subscribe to topics and start an infinite loop to pull data from the MQTT broker."""
        lp = f"{self.lp}start_sub:"
        await self.client.subscribe(
            [
                (f"{self.topic}/set/#", QOS_1),
                (f"{self.topic}/cmnd/#", QOS_1),
                (f"{self.topic}/devices", QOS_1),
                (f"{self.topic}/shutdown", QOS_1),
                (f"{self.ha_topic}/status", QOS_1),
            ]
        )
        logger.debug(f"{lp} Subscribed to topics, setting up MQTT message handler...")
        try:
            while True:
                # Grab message when it arrives
                message: amqtt.session.ApplicationMessage = (
                    await self.client.deliver_message()
                )
                if message:
                    # release event loop
                    await asyncio.sleep(0)
                    # push message onto sub_queue for processing by sub_worker task
                    self.sub_queue.put_nowait(message)
        except asyncio.CancelledError:
            logger.info(f"{lp} Caught task.cancel()...")
        except Exception as ce:
            logger.error("%s Client exception: %s" % (lp, ce))
        logger.debug(f"{lp} start_subscribing() finished")

    async def stop(self):
        lp = f"{self.lp}stop:"
        # set all devices offline
        logger.debug(f"{lp} Setting all devices offline...")
        for device_id, device in g.server.devices.items():
            availability = b"offline"
            device_uuid = f"{device.home_id}-{device.id}"
            _ = await self.client.publish(
                f"{self.topic}/availability/{device_uuid}", availability, qos=QOS_0
            )
        logger.info(f"{lp} Unsubscribing from MQTT topics...")
        await asyncio.sleep(0)
        try:
            await self.client.unsubscribe(
                [
                    f"{self.topic}/set/#",
                    f"{self.topic}/cmnd/#",
                    f"{self.topic}/devices",
                    f"{self.topic}/shutdown",
                    f"{self.ha_topic}/status",
                ]
            )
            logger.debug(
                f"{lp} Unsubscribed from topics, cancelling mqtt tasks and calling disconnect..."
            )
            await self.client.cancel_tasks()
            await self.client.disconnect()
        except Exception as e:
            logger.warning("%s MQTT disconnect failed: %s" % (lp, e))

        # Wait until the queue is fully processed.
        logger.debug(f"{lp} Waiting for pub_queue to finish...")
        await self.pub_queue.join()
        logger.debug(f"{lp} pub_queue finished, waiting for sub_queue...")
        await self.sub_queue.join()
        logger.debug(f"{lp} sub_queue finished, waiting...")
        # Cancel our worker tasks.
        for task in self.tasks:
            if task.done():
                continue
            task.cancel()
        # Wait until all worker tasks are cancelled.
        await asyncio.gather(*self.tasks, return_exceptions=True)
        logger.debug(f"{lp} All tasks finished, signalling exit for loop.stop()...")
        self.shutdown_complete = True

    async def pub_worker(self, *args, **kwargs):
        """Device status reported, publish to MQTT."""
        lp = f"{self.lp}pub:"
        logger.debug(f"{lp} Starting pub_worker...")
        while True:
            try:
                device_status: DeviceStatus
                (device_id, device_status) = await self.pub_queue.get()
                # logger.debug(
                #     f"{lp} Device ID: {device_id} status received from HTTP => {device_status}"
                # )
                await self.parse_device_status(device_id, device_status)

            except Exception as e:
                logger.error("%s pub_worker exception: %s" % (lp, e), exc_info=True)
                break
            finally:
                # Notify the queue that the "work item" has been processed.
                self.pub_queue.task_done()
                # logger.debug(f"{lp} pub_queue.task_done() called")
        logger.critical(f"{lp} pub_worker finished")

    async def parse_device_status(
        self, device_id: int, device_status: DeviceStatus, *args, **kwargs
    ) -> None:
        """Parse device status and publish to MQTT for HASS devices to update."""
        lp = f"{self.lp}parse status:"
        if device_id not in g.server.devices:
            logger.error(
                f"{lp} Device ID {device_id} not found! Device may be disbaled in config file or "
                f"you may need to re-export devices from your Cync account"
            )
            return
        device: CyncDevice = g.server.devices[device_id]
        device_uuid = f"{device.home_id}-{device_id}"
        power_status = "OFF" if device_status.state == 0 else "ON"
        mqtt_dev_state = {"state": power_status}
        tpc = f"{self.topic}/status/{device_uuid}"

        if device.is_plug:
            mqtt_dev_state = power_status.encode()
            # try:
            #     await asyncio.wait_for(
            #         self.client.publish(
            #             tpc,
            #             power_status.encode(),
            #             qos=QOS_0,
            #             # retain=True,
            #         ),
            #         timeout=3.0,
            #     )
            # except asyncio.TimeoutError:
            #     logger.exception(f"{lp} Timeout waiting for MQTT publish")
            # except Exception as e:
            #     logger.exception(f"{lp} publish exception: {e}")

        else:
            if device_status.brightness is not None:
                mqtt_dev_state["brightness"] = device_status.brightness

            if device_status.temperature is not None:
                if device.supports_rgb and (
                    any(
                        [
                            device_status.red is not None,
                            device_status.green is not None,
                            device_status.blue is not None,
                        ]
                    )
                    and device_status.temperature > 100
                ):
                    mqtt_dev_state["color_mode"] = "rgb"
                    mqtt_dev_state["color"] = {
                        "r": device_status.red,
                        "g": device_status.green,
                        "b": device_status.blue,
                    }
                elif device.supports_temperature and (
                    0 <= device_status.temperature <= 100
                ):
                    mqtt_dev_state["color_mode"] = "color_temp"
                    mqtt_dev_state["color_temp"] = self.tlct_to_hassct(
                        device_status.temperature
                    )
            mqtt_dev_state = json.dumps(mqtt_dev_state).encode()
        # logger.debug(
        #     f"{lp} Converting HTTP status to MQTT => {tpc} "
        #     + json.dumps(mqtt_dev_state)
        # )
        try:
            await asyncio.wait_for(
                self.client.publish(
                    tpc,
                    mqtt_dev_state,
                    qos=QOS_0,
                    # retain=True,
                ),
                timeout=3.0,
            )
        except asyncio.TimeoutError:
            logger.exception(f"{lp} Timeout waiting for MQTT publish")
        except Exception as e:
            logger.exception(f"{lp} publish exception: {e}")

    async def sub_worker(self, sub_queue: asyncio.Queue):
        """Process messages from MQTT"""
        lp: str = f"{self.lp}sub:"
        logger.debug(f"{lp} Starting sub_worker...")
        while True:
            message: amqtt.session.ApplicationMessage = await sub_queue.get()
            try:
                if message is None:
                    logger.error(f"{lp} message is None, skipping...")
                else:
                    try:
                        packet: amqtt.mqtt.packet.MQTTPacket = message.publish_packet
                    except Exception as e:
                        logger.error(
                            "%s message.publish_packet exception: %s" % (lp, e)
                        )
                        continue
                    topic = packet.variable_header.topic_name.split("/")
                    payload = packet.payload.data
                    logger.debug(
                        f"{lp} Received: {packet.variable_header.topic_name} => {payload}"
                    )

                    if len(topic) == 3:
                        if topic[0] == CYNC_TOPIC:
                            # command channel to send raw data to device
                            if topic[1] == "cmnd":
                                cmnd_type = topic[2]
                                if cmnd_type == "int":
                                    # check if commas
                                    if b"," in payload:
                                        # convert from string of comma separated ints to bytearray
                                        payload = bytearray(
                                            [int(x) for x in payload.split(b",")]
                                        )
                                    else:
                                        payload = bytearray(
                                            [int(x) for x in payload.split(b" ")]
                                        )
                                elif cmnd_type == "bytes":
                                    payload = bytes(payload)
                                elif cmnd_type == "hex":
                                    payload = bytes.fromhex(payload.decode())

                            elif topic[1] == "set":
                                device_id = int(topic[2].split("-")[1])
                                if device_id not in g.server.devices:
                                    logger.warning(
                                        f"{lp} Device ID {device_id} not found, device is disabled in config file or have you deleted or added any "
                                        f"devices recently?"
                                    )
                                    continue
                                device = g.server.devices[device_id]
                                if payload.startswith(b"{"):
                                    try:
                                        json_data = json.loads(payload)
                                    except Exception as e:
                                        logger.error(
                                            "%s bad json message: {%s} EXCEPTION => %s"
                                            % (lp, payload, e)
                                        )
                                        continue

                                    if "state" in json_data and "brightness" not in json_data:
                                        if json_data["state"].upper() == "ON":
                                            logger.debug(f"{lp} setting power to ON")
                                            await device.set_power(1)
                                        else:
                                            logger.debug(f"{lp} setting power to OFF")
                                            await device.set_power(0)
                                    if "brightness" in json_data:
                                        lum = int(json_data["brightness"])
                                        logger.debug(
                                            f"{lp} setting brightness to: {lum}"
                                        )
                                        # if 5 > lum > 0:
                                        #     lum = 5
                                        try:
                                            await device.set_brightness(lum)
                                        except Exception as e:
                                            logger.error(
                                                f"{lp} set_brightness exception: {e}",
                                                exc_info=True,
                                            )
                                    if "color_temp" in json_data:
                                        logger.debug(
                                            f"{lp} setting color temp to: {json_data['color_temp']}"
                                        )
                                        await device.set_temperature(
                                            self.hassct_to_tlct(
                                                int(json_data["color_temp"])
                                            )
                                        )
                                    elif "color" in json_data:
                                        color = []
                                        for rgb in ("r", "g", "b"):
                                            if rgb in json_data["color"]:
                                                color.append(
                                                    int(json_data["color"][rgb])
                                                )
                                            else:
                                                color.append(0)
                                        logger.debug(f"{lp} setting RGB to: {color}")
                                        await device.set_rgb(*color)
                                # handle non json OFF/ON payloads
                                elif payload.upper() == b"ON":
                                    logger.debug(f"{lp} setting power to ON")
                                    await device.set_power(1)
                                elif payload.upper() == b"OFF":
                                    logger.debug(f"{lp} setting power to OFF")
                                    await device.set_power(0)
                                else:
                                    logger.warning(
                                        f"{lp} Unknown payload: {payload}, skipping..."
                                    )
                                # make sure next command doesn't come too fast
                                await asyncio.sleep(0.05)

                    elif len(topic) == 2:
                        if topic[0] == CYNC_TOPIC:
                            if topic[1] == "shutdown":
                                logger.info(
                                    "sub worker - Shutdown requested, sending SIGTERM"
                                )
                                os.kill(os.getpid(), signal.SIGTERM)
                            elif topic[1] == "devices" and payload.lower() == b"get":
                                await self.publish_devices()
                        elif topic[0] == self.ha_topic:
                            if topic[1] == CYNC_HASS_STATUS_TOPIC:
                                if (
                                    payload.decode().casefold()
                                    == CYNC_HASS_BIRTH_MSG.casefold()
                                ):
                                    logger.info(
                                        f"{lp} HASS has announced online, re-announce device availability and status"
                                    )
                                    # register devices
                                    await self.homeassistant_discovery()
                                    await asyncio.sleep(0.07)
                                    # set the device online/offline and set its status
                                    for device in g.server.devices.values():
                                        await self.pub_online(device.id, device.online)
                                        await self.parse_device_status(
                                            device.id,
                                            DeviceStatus(
                                                state=device.state,
                                                brightness=device.brightness,
                                                temperature=device.temperature,
                                                red=device.red,
                                                green=device.green,
                                                blue=device.blue,
                                            ),
                                        )

                                elif (
                                    payload.decode().casefold()
                                    == CYNC_HASS_WILL_MSG.casefold()
                                ):
                                    logger.info(
                                        f"{lp} HASS is offline, received Last Will and Testament msg"
                                    )
                                else:
                                    logger.warning(
                                        f"{lp} Unknown HASS status message: {payload}"
                                    )

            except Exception as e:
                logger.error("%s sub_worker exception: %s" % (lp, e), exc_info=True)
            finally:
                # Notify the queue that the "work item" has been processed.
                sub_queue.task_done()
                logger.debug(f"{lp} sub_queue.task_done() called...")
        logger.critical(f"{lp} sub_worker finished")

    async def publish_devices(self):
        lp = f"{self.lp}publish_devices:"
        for device in g.server.devices.values():
            device_uuid = f"{device.home_id}-{device.id}"
            device_config = {
                "name": device.name,
                "id": device_uuid,
                "mac": device.mac,
                "is_plug": device.is_plug,
                "supports_rgb": device.supports_rgb,
                "supports_temperature": device.supports_temperature,
                "online": device.online,
                "brightness": device.brightness,
                "red": device.red,
                "green": device.green,
                "blue": device.blue,
                "color_temp": self.tlct_to_hassct(device.temperature),
            }
            tpc = f"{self.ha_topic}/devices/{device_uuid}"
            try:
                logger.debug(f"{lp} {tpc}  " + json.dumps(device_config))
                _ = await self.client.publish(
                    tpc, json.dumps(device_config).encode(), qos=QOS_1, retain=True
                )
            except Exception as e:
                logger.error(
                    "publish devices - Unable to publish mqtt message... skipped -> %s"
                    % e
                )

    async def homeassistant_discovery(self):
        lp = f"{self.lp}hass:"
        logger.info(f"{lp} Starting discovery...")
        try:
            for device in g.server.devices.values():
                device_uuid = f"{device.home_id}-{device.id}"
                # unique_id = device.mac.replace(":", "").casefold()
                unique_id = f"{device.home_id}_{device.id}"
                obj_id = f"cync_lan_{unique_id}"
                origin_struct = {
                    "name": "cync-lan",
                    "sw_version": CYNC_VERSION,
                    "support_url": REPO_URL,
                }
                dev_fw_version = str(device.version)
                ver_str = "Unknown"
                fw_len = len(dev_fw_version)
                if fw_len == 5:
                    if dev_fw_version != 00000:
                        ver_str = f"{dev_fw_version[0]}.{dev_fw_version[1]}.{dev_fw_version[2:]}"
                elif fw_len == 2:
                    ver_str = f"{dev_fw_version[0]}.{dev_fw_version[1]}"
                device_struct = {
                    "identifiers": [unique_id],
                    "manufacturer": "Savant",
                    "connections": [("mac", device.mac.casefold())],
                    "name": device.name,
                    "sw_version": ver_str,
                    "model": type_2_str[device.type] or "Unknown",
                }
                dev_config = {
                    "object_id": obj_id,
                    # "name": device.name,
                    # set to None if only device name is relevant
                    "name": None,
                    "command_topic": "{0}/set/{1}".format(self.topic, device_uuid),
                    "state_topic": "{0}/status/{1}".format(self.topic, device_uuid),
                    "avty_t": "{0}/availability/{1}".format(self.topic, device_uuid),
                    "pl_avail": "online",
                    "pl_not_avail": "offline",
                    "state_on": "ON",
                    "state_off": "OFF",
                    "unique_id": unique_id,
                    "schema": "json",
                    "origin": origin_struct,
                    "device": device_struct,
                    "optimistic": False,
                }
                dev_type = "light"
                tpc_str_template = "{0}/{1}/{2}/config"

                if device.is_plug:
                    dev_type = "switch"
                else:
                    dev_config.update({"brightness": True, "brightness_scale": 100})
                    if device.supports_temperature or device.supports_rgb:
                        # hass has deprecated color-mode in device config
                        # light_config["color_mode"] = True
                        dev_config["supported_color_modes"] = []
                        if device.supports_temperature:
                            dev_config["supported_color_modes"].append("color_temp")
                            dev_config["max_mireds"] = self.hass_maxct
                            dev_config["min_mireds"] = self.hass_minct
                        if device.supports_rgb:
                            dev_config["supported_color_modes"].append("rgb")

                tpc = tpc_str_template.format(self.ha_topic, dev_type, device_uuid)
                try:
                    _ = await self.client.publish(
                        tpc, json.dumps(dev_config).encode(), qos=QOS_1, retain=True
                    )
                except Exception as e:
                    logger.error(
                        "%s - Unable to publish mqtt message... skipped -> %s" % (lp, e)
                    )
                # logger.debug(
                #     f"{lp} {tpc}  "
                #     + json.dumps(dev_cfg)
                # )
        except Exception as e:
            logger.error(f"{lp} Discovery failed: {e}", exc_info=True)
        logger.debug(f"{lp} Discovery complete")

    def hassct_to_tlct(self, ct):
        # convert HASS mired range to percent range
        # Cync light is 2000K (1%) to 7000K (100%)
        # Cync light is cync_max_mired (1%) to cync_min_mired (100%)
        scale = 99 / (self.cync_max_mired - self.cync_min_mired)
        return 100 - int(scale * (ct - self.cync_min_mired))

    def tlct_to_hassct(self, ct):
        """
        Convert Cync percent range (1-100) to HASS mired range
        Cync light is 2000K (1%) to 7000K (100%)
        Cync light is cync_max_mired (1%) to cync_min_mired (100%)
        """
        if ct == 0:
            return self.cync_max_mired
        elif ct > 100:
            return self.cync_min_mired

        scale = (self.cync_min_mired - self.cync_max_mired) / 99
        return self.cync_max_mired + int(scale * (ct - 1))


def parse_cli():
    from argparse import ArgumentParser

    parser = ArgumentParser(description="Cync LAN server")
    # create a sub parser for running normally or for exporting a config from the cloud service.
    subparsers = parser.add_subparsers(dest="command", help="sub-command help")
    subparsers.required = True
    sub_run = subparsers.add_parser("run", help="Run the Cync LAN server")
    sub_run.add_argument("config", type=Path, help="Path to the configuration file")
    sub_run.add_argument(
        "-d", "--debug", action="store_true", help="Enable debug logging"
    )

    sub_export = subparsers.add_parser(
        "export",
        help="Export Cync devices from the cloud service, Requires email and/or OTP from email",
    )
    sub_export.add_argument("output_file", type=Path, help="Path to the output file")
    sub_export.add_argument(
        "--email",
        "-e",
        help="Email address for Cync account, will send OTP to email provided",
        dest="email",
    )
    sub_export.add_argument(
        "--password", "-P", help="Password for Cync account", dest="password"
    )

    sub_export.add_argument(
        "--code" "--otp", "-o", "-c", help="One Time Password from email", dest="code"
    )
    sub_export.add_argument(
        "--save-auth",
        "-s",
        action="store_true",
        help="Save authentication token to file",
        dest="save_auth",
    )
    sub_export.add_argument(
        "--auth-output",
        "-a",
        dest="auth_output",
        help="Path to save the authentication data",
        type=Path,
    )
    sub_export.add_argument(
        "--auth", help="Path to the auth token file", type=Path, dest="auth_file"
    )
    sub_export.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()
    return args


if __name__ == "__main__":

    if sys.version_info >= (3, 8):
        pass
    else:
        sys.exit(
            "Python version 3.8 or higher REQUIRED! you have version: %s" % sys.version
        )

    cli_args = parse_cli()
    if cli_args.debug and CYNC_DEBUG is False:
        logger.info("main: --debug flag - setting log level to DEBUG")
        CYNC_DEBUG = True

    if CYNC_DEBUG is True:
        logger.setLevel(logging.DEBUG)
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)
    if cli_args.command == "run":
        config_file: Optional[Path] = cli_args.config
        if not config_file.exists():
            raise FileNotFoundError(f"Config file not found: {config_file}")
        elif not config_file.is_file():
            raise ValueError(f"Config file is not a file: {config_file}")
        elif not config_file.is_absolute():
            config_file = config_file.expanduser().resolve()

        g = GlobalState()
        global_tasks = []
        cync = CyncLAN(config_file)
        loop: uvloop.Loop = cync.loop
        logger.debug("main: Setting up event loop signal handlers")
        loop.add_signal_handler(
            signal.SIGINT, partial(cync.signal_handler, signal.SIGINT)
        )
        loop.add_signal_handler(
            signal.SIGTERM, partial(cync.signal_handler, signal.SIGTERM)
        )
        try:
            cync.start()
            cync.loop.run_forever()
        except KeyboardInterrupt as ke:
            logger.info("main: Caught KeyboardInterrupt in exception block!")
            raise KeyboardInterrupt from ke

        except Exception as e:
            logger.warning(
                "main: Caught exception in __main__ cync.start() try block: %s" % e,
                exc_info=True,
            )
        finally:
            if cync and not cync.loop.is_closed():
                logger.debug("main: Closing loop...")
                cync.loop.close()
    elif cli_args.command == "export":
        logger.debug("main: Exporting Cync devices from cloud service...")
        cloud_api = CyncCloudAPI()
        cli_email: Optional[str] = cli_args.email
        cli_otp_code: Optional[str] = cli_args.code
        cli_password: Optional[str] = cli_args.password
        save_auth: bool = cli_args.save_auth
        auth_output: Optional[Path] = cli_args.auth_file
        auth_file: Optional[Path] = cli_args.auth_file
        access_token = None
        token_user = None

        try:
            if not auth_file:
                access_token, token_user = cloud_api.authenticate_2fa(
                    uname=cli_email, otp_code=cli_otp_code
                )
            else:
                raw_file_yaml = yaml.safe_load(auth_file.read_text())
                access_token = raw_file_yaml["token"]
                token_user = raw_file_yaml["user"]
            if not access_token or not token_user:
                raise ValueError(
                    "main: Failed to authenticate, no token or user found. Check auth file or email/OTP"
                )

            logger.info(
                f"main: Cync Cloud API auth data => user: {token_user} // token: {access_token}"
            )

            mesh_networks = cloud_api.get_devices(
                user=token_user, auth_token=access_token
            )
            for mesh in mesh_networks:
                mesh["properties"] = cloud_api.get_properties(
                    access_token, mesh["product_id"], mesh["id"]
                )

            mesh_config = cloud_api.mesh_to_config(mesh_networks)
            output_file: Path = cli_args.output_file
            logger.info(f"about to dump cloud export to file: {mesh_config = }")
            with output_file.open("w") as f:
                f.write(
                    "# BE AWARE - the config file will overwrite any env vars set!\n"
                    "# If your MQTT broker is using auth -> mqtt_url: mqtt://user:pass@homeassistant.local:1883/\n"
                    "#mqtt_url: mqtt://homeassistant.local:1883/\n\n"
                )
                f.write(yaml.dump(mesh_config))

        except Exception as e:
            logger.error(f"main: Export failed: {e}", exc_info=True)
        else:
            logger.info(f"main: Exported Cync devices to file: {cli_args.output_file}")

        if save_auth:
            if not auth_output:
                auth_output = Path.cwd() / "cync_auth.yaml"

            else:
                logger.info(
                    "main: Attempting to save Cync Cloud Auth to file, PLEASE SECURE THIS FILE!"
                )
                try:
                    with auth_output.open("w") as f:
                        f.write(yaml.dump({"token": access_token, "user": token_user}))
                except Exception as e:
                    logger.error(
                        "Failed to save auth token to file: %s" % e, exc_info=True
                    )
                else:
                    logger.info(
                        f"Saved auth token to file: {Path.cwd()}/cync_auth.yaml"
                    )
