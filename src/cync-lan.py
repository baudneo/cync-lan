#!/usr/bin/env python3
import ast
import asyncio
import datetime
import getpass
import json
import logging
import os
import random
import re
import signal
import ssl
import struct
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from functools import partial
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
CYNC_VERSION: str = __version__
REPO_URL: str = "https://github.com/baudneo/cync-lan"
LWT_MSG: bytes = b"offline"
# This will run an async task every x seconds to check if any device is offline or online.
# Hopefully keeps devices in sync (seems to do pretty good).
CYNC_MESH_CHECK_INTERVAL: int = int(os.environ.get("CYNC_MESH_CHECK", 30)) or 30
CYNC_MQTT_URL = os.environ.get("CYNC_MQTT_URL", "mqtt://homeassistant.local:1883")
CYNC_CERT = os.environ.get("CYNC_CERT", "certs/cert.pem")
CYNC_KEY = os.environ.get("CYNC_KEY", "certs/key.pem")
CYNC_TOPIC = os.environ.get("CYNC_TOPIC", "cync_lan")
CYNC_HASS_TOPIC = os.environ.get("CYNC_HASS_TOPIC", "homeassistant")
CYNC_PORT = os.environ.get("CYNC_PORT", 23779)
CYNC_HOST = os.environ.get("CYNC_HOST", "0.0.0.0")
CYNC_CHUNK_SIZE = os.environ.get("CYNC_CHUNK_SIZE", 2048)
YES_ANSWER = ("true", "1", "yes", "y", "t", 1)
CYNC_RAW = os.environ.get("CYNC_RAW_DEBUG", "0").casefold() in YES_ANSWER
CYNC_DEBUG = os.environ.get("CYNC_DEBUG", "0").casefold() in YES_ANSWER
CORP_ID: str = "1007d2ad150c4000"
DATA_BOUNDARY = 0x7E

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
# set library loggers to INFO


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

def parse_firmware_version(data_struct: bytes, lp: str) -> Optional[Tuple[str, int, str]]:
    """Parse the firmware version from binary hex data."""
    lp = f"{lp}firmware_version:"
    if data_struct[0] != 0x00:
        logger.error(f"{lp} Invalid first byte value: {data_struct[0]} should be 0x00 for firmware version data")

    n_idx = 20  # Starting index for firmware information
    firmware_type = "device" if data_struct[n_idx + 2] == 0x01 else "network"
    n_idx += 3

    firmware_version = []
    try:
        while len(firmware_version) < 5 and data_struct[n_idx] != 0x00:
            firmware_version.append(int(chr(data_struct[n_idx])))
            n_idx += 1
        if not firmware_version:
            logger.warning(f"{lp} No firmware version found in packet: {data_struct.hex(' ')}")
            return None

    except (IndexError, ValueError) as e:
        logger.error(f"{lp} Exception occurred while parsing firmware version: {e}")
        return None

    else:
        firmware_str = f"{firmware_version[0]}.{firmware_version[1]}.{''.join(map(str, firmware_version[2:]))}"
        firmware_version_int = int("".join(map(str, firmware_version)))
        logger.debug(f"{lp} {firmware_type} firmware VERSION: {firmware_version_int} ({firmware_str})")

    return firmware_type, firmware_version_int, firmware_str


@dataclass
class MeshInfo:
    status: List[Optional[List[Optional[int]]]]
    id_from: int


class PhoneAppStructs:
    @dataclass
    class AppRequests:
        auth_header: bytes = bytes([0x13, 0x00, 0x00, 0x00])
        connect_header: bytes = bytes([0xA3, 0x00, 0x00, 0x00])

    @dataclass
    class AppResponses:
        auth_resp: bytes = bytes([0x18, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00])
        # connect response needs toe xtract the queue id from the request

    requests: AppRequests = AppRequests()
    responses: AppResponses = AppResponses()


class DeviceStructs:
    def __iter__(self):
        return iter([self.requests, self.responses])

    @dataclass
    class DeviceRequests:
        """These are packets devices send to the server"""

        x23: bytes = bytes([0x23])
        xc3: bytes = bytes([0xC3])
        xd3: bytes = bytes([0xD3])
        x83: bytes = bytes([0x83])
        x73: bytes = bytes([0x73])
        x7b: bytes = bytes([0x7B])
        x43: bytes = bytes([0x43])
        xa3: bytes = bytes([0xA3])
        xab: bytes = bytes([0xAB])
        auth_header: bytes = x23
        _headers: Tuple[bytes] = (x23, xc3, xd3, x83, x73, x7b, x43, xa3, xab)

        def __iter__(self):
            return iter(self._headers)

    @dataclass
    class DeviceResponses:
        """These are the packets the server sends to the device"""

        auth_ack: bytes = bytes([0x28, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00])
        # todo: figure out correct bytes for this
        connection_ack: bytes = bytes(
            [
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
            ]
        )
        x48_ack: bytes = bytes([0x48, 0x00, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00])
        x88_ack: bytes = bytes([0x88, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00])
        ping_ack: bytes = bytes([0xD8, 0x00, 0x00, 0x00, 0x00])
        # 78 and 7b still need definition
        x78_base: bytes = bytes([0x78, 0x00, 0x00, 0x00])
        x7b_base: bytes = bytes([0x7B, 0x00, 0x00, 0x00, 0x07])

    requests: DeviceRequests = DeviceRequests()
    responses: DeviceResponses = DeviceResponses()

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
        dlen = len(queue_id) + len(msg_id) + len(bytes.fromhex(hex_str.replace(' ', '')))
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


class MessageCallback:
    id: int
    original_message: Union[None, str, bytes, List[int]] = None
    sent_at: Optional[float] = None
    callback: Optional[Callable[..., Coroutine[Any, Any, None]]] = None

    args: List = []
    kwargs: Dict = {}

    def __str__(self):
        return f"MessageCallback:{self.id}: {self.callback}"

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
    x73: List[MessageCallback] = []


class CyncCloudAPI:
    api_timeout: int = 5

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

    def authenticate_2fa(self, *args, **kwargs):  # noqa
        """Authenticate with the API and get a token."""
        username = input("Enter Username/Email (or emailed OTP code):")
        if re.match(r"^\d+$", username):
            # if username is all digits, assume it's a OTP code
            otp_code = str(username)
            username = input("Enter Username/Email:")
        else:
            # Ask to be sent an email with OTP code
            api_auth_url = "https://api.gelighting.com/v2/two_factor/email/verifycode"
            auth_data = {"corp_id": CORP_ID, "email": username, "local_lang": "en-us"}
            requests.post(api_auth_url, json=auth_data, timeout=self.api_timeout)
            otp_code = input("Enter emailed OTP code:")

        password = getpass.getpass()
        api_auth_url = "https://api.gelighting.com/v2/user_auth/two_factor"
        auth_data = {
            "corp_id": CORP_ID,
            "email": username,
            "password": password,
            "two_factor": otp_code,
            "resource": random_login_resource(),
        }
        r = requests.post(api_auth_url, json=auth_data, timeout=self.api_timeout)

        try:
            return r.json()["access_token"], r.json()["user_id"]
        except KeyError:
            raise Exception("API authentication failed")

    def get_devices(self, auth_token: str, user: str):
        """Get a list of devices for a particular user."""
        api_devices_url = "https://api.gelighting.com/v2/user/{user}/subscribe/devices"
        headers = {"Access-Token": auth_token}
        r = requests.get(
            api_devices_url.format(user=user), headers=headers, timeout=self.api_timeout
        )
        return r.json()

    def get_properties(self, auth_token: str, product_id: str, device_id: str):
        """Get properties for a single device."""
        api_device_info_url = "https://api.gelighting.com/v2/product/{product_id}/device/{device_id}/property"
        headers = {"Access-Token": auth_token}
        r = requests.get(
            api_device_info_url.format(product_id=product_id, device_id=device_id),
            headers=headers,
            timeout=self.api_timeout,
        )
        return r.json()

    @staticmethod
    def mesh_to_config(mesh_info):
        mesh_conf = {}
        logger.debug("Dumping raw config from Cync account to file: ./raw_mesh.cync")
        try:
            with open("./raw_mesh.cync", "w") as _f:
                _f.write(yaml.dump(mesh_info))
        except Exception as file_exc:
            logger.error("Failed to write raw mesh info to file: %s" % file_exc)
        for mesh_ in mesh_info:
            if "name" not in mesh_ or len(mesh_["name"]) < 1:
                logger.warning("No name found for mesh, skipping...")
                continue

            if "properties" not in mesh_ or "bulbsArray" not in mesh_["properties"]:
                logger.warning(
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
                _type = cfg_bulb["deviceType"]

                bulb_device = CyncDevice(
                    name=name,
                    cync_id=__id,
                    cync_type=int(_type),
                    mac=_mac,
                    wifi_mac=wifi_mac,
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
                # new_bulb["type"] = _type
                new_bulb["is_plug"] = bulb_device.is_plug
                new_bulb["supports_temperature"] = bulb_device.supports_temperature
                new_bulb["supports_rgb"] = bulb_device.supports_rgb

                new_mesh["devices"][__id] = new_bulb

        config_dict = {"account data": mesh_conf}

        return config_dict


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
            31,  # BTLE only bulb?
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
    ):
        self.control_number = 0
        if cync_id is None:
            raise ValueError("ID must be provided to constructor")
        self.id = cync_id
        self.lp = f"CyncDevice:{cync_id}:"
        self.type = cync_type
        self._mac = mac
        self.wifi_mac = wifi_mac
        if name is None:
            name = f"device_{cync_id}"
        self.name = name
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

    def get_incremental_number(self):
        """
        Control packets need a number that gets incremented, it is used as a type of msg ID and
        in calculating the checksum. Result is mod 256 in order to keep it within 0-255.
        """
        self.control_number += 1
        return self.control_number % 256

    async def set_power(self, state: int):
        """Send raw data to control device state"""
        if state not in (0, 1):
            logger.error("Invalid state! must be 0 or 1")
            return
        msg_id_inc = self.get_incremental_number()
        checksum = ((msg_id_inc - 64) + state + self.id) % 256
        header = [0x73, 0x00, 0x00, 0x00, 0x1F]
        _inner_struct = [
            0x7E,
            msg_id_inc,
            0x00,
            0x00,
            0x00,
            0xF8,
            0xD0,
            0x0D,
            0x00,
            msg_id_inc,
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
            checksum,
            0x7E,
        ]

        new_state = DeviceStatus(
            state=state,
            brightness=None,
            temperature=None,
            red=None,
            green=None,
            blue=None,
        )
        # pick a random http device to send the command to
        # it should bridge the command over btle to the device ID
        # bridge_device: "CyncHTTPDevice" = random.choice(list(g.server.http_devices.values()))
        raw_dbg = f" // {bytes(header).hex(' ')}" if CYNC_RAW else ""
        logger.debug(
            f"{self.lp} Changing power state: {self.state} to {state}{raw_dbg}"
        )
        await g.mqtt.parse_device_status(self.id, new_state)

        # # testing a callback system that determines success or failure
        # cb = MessageCallback(msg_id_inc)
        # cb.original_message = b
        # cb.sent_at = time.time()
        # cb.callback = g.mqtt.parse_device_status
        # cb.args = []
        # cb.args.extend([self.id, new_state])
        # logger.debug(
        #     f"{self.lp} Adding x73 callback (id: {msg_id_inc}) to HTTP device: {bridge_device.address} -> {cb}"
        # )
        # bridge_device.messages.x73.append(cb)

        # await bridge_device.write(b)
        for device in g.server.http_devices.values():
            header.extend(device.queue_id)
            header.extend(bytes([0x00, 0x00, 0x00]))
            header.extend(_inner_struct)
            b = bytes(header)
            await device.write(b)

    async def set_brightness(self, bri: int):
        """Send raw data to control device brightness"""
        #  73 00 00 00 22 37 96 24 69 60 48 00 7e 17 00 00  s..."7.$i`H.~...
        #  00 f8 f0 10 00 17 00 00 00 00 07 00 f0 11 02 01  ................
        #  27 ff ff ff ff 45 7e
        # lp = f"{self.lp}set_brightness:"
        msg_id_inc = self.get_incremental_number()
        checksum = (msg_id_inc + bri + self.id) % 256
        header = [115, 0, 0, 0, 34]
        inner_struct = [
            126,
            msg_id_inc,
            0,
            0,
            0,
            248,
            240,
            16,
            0,
            msg_id_inc,
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
            checksum,
            126,
        ]
        new_state = DeviceStatus(
            state=None,
            brightness=bri,
            temperature=None,
            red=None,
            green=None,
            blue=None,
        )
        # bridge_device: "CyncHTTPDevice" = random.choice(list(g.server.http_devices.values()))
        raw_dbg = f" // {bytes(header).hex(' ')}" if CYNC_RAW else ""
        logger.debug(f"{self.lp} Changing brightness: {self._brightness} to {bri}{raw_dbg}")
        await g.mqtt.parse_device_status(self.id, new_state)
        # # testing a callback system that determines success or failure
        # cb = MessageCallback(msg_id_inc)
        # cb.original_message = b
        # cb.sent_at = time.time()
        # cb.callback = g.mqtt.parse_device_status
        # cb.args = []
        # cb.args.extend([self.id, new_state])
        # logger.debug(
        #     f"{self.lp} Adding x73 callback to HTTP device: {bridge_device.address} -> {cb}"
        # )
        # bridge_device.messages.x73.append(cb)

        for device in g.server.http_devices.values():
            header.extend(device.queue_id)
            header.extend(bytes([0x00, 0x00, 0x00]))
            header.extend(inner_struct)
            b = bytes(header)
            await device.write(b)
        # await bridge_device.write(b)

    async def set_temperature(self, temp: int):
        """Send raw data to control device brightness"""
        #  73 00 00 00 22 37 96 24 69 60 8d 00 7e 36 00 00  s..."7.$i`..~6..
        #  00 f8 f0 10 00 36 00 00 00 00 07 00 f0 11 02 01  .....6..........
        #  ff 48 00 00 00 88 7e                             .H....~
        # checksum = 0x88 = 136
        # 0x36 0x48 0x07 = 54 + 72 + 7 = 133 (needs + 3)

        msg_id_inc = self.get_incremental_number()
        checksum = ((msg_id_inc + temp + self.id) + 3) % 256
        header = [115, 0, 0, 0, 34]
        inner_struct = [
            126,
            msg_id_inc,
            0,
            0,
            0,
            248,
            240,
            16,
            0,
            msg_id_inc,
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
            checksum,
            126,
        ]
        new_state = DeviceStatus(
            state=None,
            brightness=None,
            temperature=temp,
            red=None,
            green=None,
            blue=None,
        )
        # pick a random http device to send the command to
        # it should bridge the command over btle to the device ID
        # bridge_device: "CyncHTTPDevice" = random.choice(list(g.server.http_devices.values()))
        raw_dbg = f" // {bytes(header).hex(' ')}" if CYNC_RAW else ""
        logger.debug(
            f"{self.lp} Changing white temperature: {self.temperature} to {temp}{raw_dbg}"
        )
        await g.mqtt.parse_device_status(self.id, new_state)
        # # testing a callback system that determines success or failure
        # cb = MessageCallback(msg_id_inc)
        # cb.original_message = b
        # cb.sent_at = time.time()
        # cb.callback = g.mqtt.parse_device_status
        # cb.args = []
        # cb.args.extend([self.id, new_state])
        # logger.debug(
        #     f"{self.lp} Adding x73 callback to HTTP device: {bridge_device.address} -> {cb}"
        # )
        # bridge_device.messages.x73.append(cb)
        for device in g.server.http_devices.values():
            header.extend(device.queue_id)
            header.extend(bytes([0x00, 0x00, 0x00]))
            header.extend(inner_struct)
            b = bytes(header)
            await device.write(b)

    async def set_rgb(self, red: int, green: int, blue: int):
        """

         73 00 00 00 22 37 96 24 69 60 79 00 7e 2b 00 00  s..."7.$i`y.~+..
         00 f8 f0 10 00 2b 00 00 00 00 07 00 f0 11 02 01  .....+..........
        ff fe 00 fb ff 2d 7e                             .....-~

        checksum = 45

        2b 07 00 fb ff = 43 + 7 + 0 + 251 + 255 = 556 ( needs + 1)
        """
        msg_id_inc = self.get_incremental_number()
        checksum = ((msg_id_inc + self.id + red + green + blue) + 1) % 256
        header = [115, 0, 0, 0, 34]
        inner_struct = [
            126,
            msg_id_inc,
            0,
            0,
            0,
            248,
            240,
            16,
            0,
            msg_id_inc,
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
            checksum,
            126,
        ]
        new_state = DeviceStatus(
            state=None,
            brightness=None,
            temperature=254,
            red=red,
            green=green,
            blue=blue,
        )
        # pick a random http device to send the command to
        # it should bridge the command over btle to the device ID
        # bridge_device: "CyncHTTPDevice" = random.choice(list(g.server.http_devices.values()))
        raw_dbg = f" // {bytes(header).hex(' ')}" if CYNC_RAW else ""
        logger.debug(
            f"{self.lp} Changing RGB: {self.red}, {self.green}, {self.blue} to {red}, {green}, {blue}{raw_dbg}"
        )
        await g.mqtt.parse_device_status(self.id, new_state)
        # # testing a callback system that determines success or failure
        # cb = MessageCallback(msg_id_inc)
        # cb.original_message = b
        # cb.sent_at = time.time()
        # cb.callback = g.mqtt.parse_device_status
        # cb.args = []
        # cb.args.extend([self.id, new_state])
        # logger.debug(
        #     f"{self.lp} Adding x73 callback to HTTP device: {bridge_device.address} -> {cb}"
        # )
        # bridge_device.messages.x73.append(cb)

        for bridge_device in g.server.http_devices.values():
            header.extend(bridge_device.queue_id)
            header.extend(bytes([0x00, 0x00, 0x00]))
            header.extend(inner_struct)
            b = bytes(header)
            await bridge_device.write(b)

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
                f"Device ID: {_id} not found in devices!? consider re-exporting your Cync account devices! "
                f"or there is a bug!"
            )
            return

        if connected_to_mesh == 0:
            # This usually happens when a device loses power/connection.
            # this device is gone, need to mark it offline.
            bt_only = device.is_bt_only()
            dev_type = "WiFi/BT" if not bt_only else "BT only"
            if device.online:
                logger.warning(
                    f"{self.lp} Device ID: {_id} is {dev_type}, it seems to have been removed from the "
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
            new_state = DeviceStatus(
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
                # logger.debug(f"{device.lp} NO CHANGES TO DEVICE STATUS")
                pass
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
            if whats_changed:
                logger.debug(
                    f"{device.lp} CHANGES TO DEVICE STATUS: {', '.join(whats_changed)} -> {new_state} "
                    f"// OLD = {curr_status}"
                )
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
        """A function that is to be run as an async task to ask each device for its mesh info"""
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
                    f"{lp} Asking all ({len(http_dev_keys)}) HTTP devices for their "
                    f"mesh info: {', '.join(http_dev_keys).rstrip(',')}"
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
                for cfg_id in ids_from_config:
                    availability_info[cfg_id] = cfg_id in self.known_ids
                    if not availability_info[cfg_id]:
                        offline_ids.append(cfg_id)
                    await g.mqtt.pub_online(cfg_id, availability_info[cfg_id])

                offline_str = (
                    f" offline ({len(offline_ids)}): {sorted(offline_ids)} //"
                    if offline_ids
                    else ""
                )

                for known_id in self.known_ids:
                    if known_id not in ids_from_config:
                        logger.warning(
                            f"{lp} Device {known_id} not found in config file! You may need to "
                            f"export the devices again OR there is a bug."
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
        if remove_idx:
            for idx in remove_idx:
                del g.mqtt.tasks[idx]
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
                f" see any, check your DNS redirection and firewall settings (Different VLANs?)."
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

        self._ids_from_config: List[Optional[int]] = []
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
            cfg_id = cfg["id"]
            if "devices" not in cfg:
                logger.warning(
                    f"{self.lp} No devices found in config for: {cfg_name} (ID: {cfg_id}), skipping..."
                )
                continue
            if "name" not in cfg:
                cfg["name"] = f"mesh_{cfg_id}"
            # Create devices
            for cync_id, cync_device in cfg["devices"].items():
                self._ids_from_config.append(cync_id)
                device_type = cync_device["type"] if "type" in cync_device else None
                # mac = cync_device["mac"] if "mac" in cync_device else None
                # wifi_mac = (
                #     cync_device["wifi_mac"] if "wifi_mac" in cync_device else None
                # )
                # ip = cync_device["ip"] if "ip" in cync_device else None
                device_name = (
                    cync_device["name"]
                    if "name" in cync_device
                    else f"device_{cync_id}"
                )
                new_device = CyncDevice(
                    name=device_name, cync_id=cync_id, cync_type=device_type
                )
                for attrset in (
                    "is_plug",
                    "supports_temperature",
                    "supports_rgb",
                    "mac",
                    "wifi_mac",
                    "ip",
                    "bt_only",
                ):
                    if attrset in cync_device:
                        setattr(new_device, attrset, cync_device[attrset])
                devices[cync_id] = new_device

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

    def __init__(
        self,
        reader: Optional[asyncio.StreamReader] = None,
        writer: Optional[asyncio.StreamWriter] = None,
        address: Optional[str] = None,
    ):
        self.network_version_str: Optional[str] = None
        self.inc_bytes: Optional[Union[int, bytes, str]] = None
        self.version: Optional[int] = None
        self.version_str: Optional[str] = None
        self.network_version: Optional[int] = None
        self.device_types: Optional[dict] = None
        self.device_type_id: Optional[int] = None
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
        logger.debug(
            f"{self.lp} Created new device: {address}"
        )
        self.lp = f"{self.address}:"

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
        if CYNC_RAW is True:
            logger.debug(
                f"{lp} Extracting packets from {data_len} bytes of raw data\n{data.hex(' ')}"
            )
        if data_len < 5:
            logger.debug(
                f"{lp} Data is less than 5 bytes, not enough to parse (header: 5 bytes)"
            )
        else:
            while True:
                packet_length = data[4]
                pkt_len_multiplier = data[3]
                extract_length = ((pkt_len_multiplier * 256) + packet_length) + 5
                extracted_packet = data[:extract_length]
                if data_len > 4:
                    data = data[extract_length:]
                else:
                    data = None

                # pkt_type = data[0]
                # lp = f"{self.address}:extract:x{pkt_type:02x}:"
                # logger.debug(
                #     f"{lp} Extracted packet ({packet_length=} / {extract_length = }): {extracted_packet}"
                # )
                await self.parse_packet(extracted_packet)
                if not data:
                    break
                # logger.debug(f"{lp} Remaining data: {data}")

    async def parse_packet(self, data: bytes):
        """Parse what type of packet based on header (first 4 bytes)"""

        lp = f"{self.lp}parse:x{data[0]:02x}:"
        packet_data: Optional[bytes] = None
        pkt_header_len = 12
        packet_header = data[:pkt_header_len]
        # logger.debug(f"{lp} Parsing packet header: {packet_header.hex(' ')}")
        # byte 1 (2, 3 are unknown)
        pkt_type = int(packet_header[0]).to_bytes(1, "big")
        # byte 4
        pkt_multiplier = packet_header[3] * 256
        # byte 5
        packet_length = packet_header[4] + pkt_multiplier
        # byte 6-10
        queue_id = packet_header[5:10]
        # byte 10-12
        msg_id = packet_header[9:12]
        # check if any data after header
        if len(data) > pkt_header_len:
            packet_data = data[pkt_header_len:]
        else:
            # logger.warning(f"{lp} there is no data after the packet header!")
            pass
        # logger.debug(f"{lp} raw data length: {len(data)} // {data.hex(' ')}")
        # logger.debug(f"{lp} packet_data length: {len(packet_data)} // {packet_data.hex(' ')}")
        if pkt_type in DEVICE_STRUCTS.requests:
            if pkt_type == DEVICE_STRUCTS.requests.x23:
                queue_id = data[6:10]
                logger.debug(
                    f"{lp} Device AUTH packet with starting queue ID: '{queue_id.hex(' ')}'..."
                )
                self.queue_id = queue_id
                await self.write(DEVICE_STRUCTS.responses.auth_ack)
                # MUST SEND a3 before you can ask device for anything over HTTP
                await asyncio.sleep(0.5)
                await self.send_a3(queue_id)
            # device wants to connect before accepting commands
            elif pkt_type == DEVICE_STRUCTS.requests.xc3:
                conn_time_str = ""
                if self.last_xc3_request is not None:
                    elapsed = time.time() - self.last_xc3_request
                    conn_time_str = f" // Last request was {elapsed:.2f} seconds ago"
                logger.debug(f"{lp} CONNECTION REQUEST, replying...{conn_time_str}")
                self.last_xc3_request = time.time()
                await self.write(DEVICE_STRUCTS.responses.connection_ack)
            # Ping/Pong
            elif pkt_type == DEVICE_STRUCTS.requests.xd3:
                await self.write(DEVICE_STRUCTS.responses.ping_ack)
                # logger.debug(f"{lp}xd3: Client sent HEARTBEAT, replying...")
            elif pkt_type == DEVICE_STRUCTS.requests.xa3:
                logger.debug(f"{lp} APP ANNOUNCEMENT packet: {packet_data.hex(' ')}")
                ack = DEVICE_STRUCTS.xab_generate_ack(queue_id, bytes(msg_id))
                # logger.debug(f"{lp} Sending ACK -> {ack.hex(' ')}")
                await self.write(ack)
            elif pkt_type == DEVICE_STRUCTS.requests.xab:
                # We sent a 0xa3 packet, device is responding with 0xab. msg contains ascii 'xlink_dev'.
                # sometimes this is sent with other data. there may be remaining data to read in the enxt raw msg.
                # http msg buffer seems to be 1024 bytes.
                # 0xab packets are 1024 bytes long, so if any data is prepended, the remaining 0xab data will be in the next raw read
                pass
            elif pkt_type == DEVICE_STRUCTS.requests.x7b:
                # device is acking one of our x73 requests
                pass

            elif pkt_type == DEVICE_STRUCTS.requests.x43:
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


                        # [199, 144, 42, 50, 48, 50, 52, 48, 57, 48, 49, 58, 49, 56, 53, 57, 58, 45, 52, 50, 44, 48, 50, 51, 50, 50, 44, 48, 48, 48, 48, 52, 44, 48, 48, 49, 48, 51, 44, 48, 48, 48, 54, 51, 44]

                        # 32 30 32 34 30 39 30 31 3a 31 38 35 39 3a 2d 34 32 2c 30 32 33 32 32 2c 30 30 30 30 34 2c 30 30 31 30 33 2c 30 30 30 36 33
                        # 20240901:1859:-42,02322,00004,00103,00063,
                        # packet_data = 45

                        ts_idx = 3
                        ts_end_idx = -1
                        logger.debug(
                            f"{lp} Device TIMESTAMP PACKET ({len(bytes.fromhex(packet_data.hex()))}) -> HEX: "
                            f"{packet_data.hex(' ')} // INTS: {bytes2list(packet_data)} // "
                            f"ASCII: {packet_data.decode(errors='replace')}"
                        ) if CYNC_RAW is True else None
                        # if self.version >= 30000 <= 40000:
                        if self.address == "10.0.2.225":
                            ts_end_idx = -2
                        ts = packet_data[ts_idx:ts_end_idx]
                        logger.debug(
                            f"{lp} Device sent TIMESTAMP -> {ts.decode('ascii', errors='replace')} - replying..."
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
                            logger.debug(
                                f"{lp} Device sent BROADCAST STATUS packet => '{packet_data.hex(' ')}'"
                            )if CYNC_RAW is True else None
                            for i in range(0, packet_length, struct_len):
                                extracted = packet_data[i : i + struct_len]
                                if extracted:
                                    status_struct = extracted[3:11]
                                    # 14 00 10 01 00 00 64 00 00 00 01 15 15 00 00 00 00 00 00
                                    # // [1, 0, 0, 100, 0, 0, 0, 1]
                                    extractions.append((extracted.hex(' '), bytes2list(status_struct)))
                                # broadcast status data
                                # await self.write(data, broadcast=True)
                            logger.debug(
                                "%s Extracted data and STATUS struct => %s"
                                % (
                                    lp,
                                    extractions,
                                )
                            )
                        except IndexError:
                            pass
                        except Exception as e:
                            logger.error(f"{lp} EXCEPTION: {e}")
                # Its one of those queue id/msg id pings? 0x43 00 00 00 ww xx xx xx xx yy yy yy
                # Also notice these messages when another device gets a command
                else:
                    # logger.debug(f"{lp} received a 0x43 packet with no data, interpreting as PING, replying...")
                    pass
                ack = DEVICE_STRUCTS.x48_generate_ack(bytes(msg_id))
                # logger.debug(f"{lp} Sending ACK -> {ack.hex(' ')}")
                await self.write(ack)

            # When the device sends a packet starting with 0x83, data is wrapped in 0x7e.
            # firmware version is sent without 0x7e boundaries
            elif pkt_type == DEVICE_STRUCTS.requests.x83:
                if packet_data is not None:
                    logger.debug(f"{lp} DATA ({len(bytes(packet_data))} bytes) => {packet_data.hex(' ')}")
                    # 0x83 inner struct - not always bound by 0x7e (firmware response doesn't have starting boundary, has ending boundary 0x7e)
                    # firmware info, data len = 30 (0x32), fw starts idx 23-27, 20-22 fw type (86 01 0x)
                    #  {83 00 00 00 32} {[39 87 c8 57] [00 03 00]} {00 00 00 00  ....29..W.......
                    #  00 fa 00 20 00 00 00 00 00 00 00 00 ea 00 00 00  ... ............
                    #  86 01 01 31[idx=23 packet_data] 30 33 36 31 00 00 00 00 00 00 00 00  ...10361........
                    #  00 00 00 00 00 [8d] [7e]}                             ......~
                    # firmware packet may only be sent on startup / network reconnection
                    if packet_data[0] == 0x00:
                        fw_type, fw_ver, fw_str = parse_firmware_version(packet_data, lp)
                        if fw_type == 'device':
                            self.version = fw_ver
                            self.version_str = fw_str
                        else:
                            self.network_version = fw_ver
                            self.network_version_str = fw_str

                    elif packet_data[0] == 0x7E:
                        # device self status, its internal status. state can be off and brightness set to a non 0.
                        # signifies what brightness when state = on, meaning don't rely on brightness for on/off.
                        # 83 00 00 00 25 37 96 24 69 00 05 00 7e {21 00 00  ....%7.$i...~!..
                        #  00} {[fa db] 13} 00 (34 22) 11 05 00 [05] 00 db 11 02 01  .....4".........
                        #  [00 64 00 00 00 00] 00 00 b3 7e

                        # full color light strip controller firmware version: 3.0.204 has byte index 1 as increment
                        # index 2 is the rollover so the value is * 256
                        inc_idx = 1
                        # if self.device_type_id == 133:
                        #     # light strip controller
                        #     inc_idx = 1
                        #
                        #     if self.version:
                        #         if self.version >= 30204:
                        #
                        #             # the next byte (idx 2) is the rollover byte (idx 2 * 256 + idx 1)
                        #             logger.debug(f"{lp} device type: {self.device_type_id} (Light Strip) has firmware version: "
                        #                          f"{self.version_str} meaning increment byte at index: "
                        #                          f"{inc_idx} ({bytes(packet_data[inc_idx])})")
                        inc_bytes = packet_data[inc_idx:inc_idx + 4]
                        self.inc_bytes = inc_bytes
                        # logger.debug(f"{lp} Increment bytes: {inc_bytes.hex(' ')}")

                        ctrl_bytes = packet_data[5:7]
                        # This has self status, but it appears to be a packet that replies to a control packet
                        # this seems to show it changed its device state in response to a control packet
                        if ctrl_bytes == bytes([0xFA, 0xDB]):
                            # 0x13 after ctrl bytes signifies self status or device status
                            if packet_data[7] == 0x13:
                                id_idx = 14
                                connected_idx = 19
                                state_idx = 20
                                bri_idx = 21
                                tmp_idx = 22
                                r_idx = 23
                                g_idx = 24
                                b_idx = 25
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
                                logger.debug(
                                    f"{lp} Internal STATUS for device ID: {dev_id} = {bytes2list(raw_status)}"
                                )
                                await g.server.parse_status(raw_status)
                            if packet_data[7] == 0x14:
                                # some sort of other message, we want to see the wrapped data
                                pass
                else:
                    logger.warning(
                        f"{lp} packet with no data????? After stripping header, queue and "
                        f"msg id, there is no data to process?????"
                    )
                ack = DEVICE_STRUCTS.x88_generate_ack(msg_id)
                # logger.debug(f"{lp} RAW DATA: {data.hex(' ')}")
                # logger.debug(f"{lp} Sending ACK -> {ack.hex(' ')}")
                await self.write(ack)

            elif pkt_type == DEVICE_STRUCTS.requests.x73:
                if packet_data is not None:
                    # 0x73 should ALWAYS have 0x7e bound data.
                    ctrl_bytes = packet_data[5:7]
                    # check for boundary, all bytes between boundaries are for this request
                    if packet_data[0] == 0x7E:
                        # find next 0x7e and extract the inner struct
                        end_bndry_idx = packet_data[1:].find(0x7E) + 1
                        inner_struct = packet_data[1:end_bndry_idx]
                        # ctrl bytes 0xf9, 0x52 indicates this is a mesh info struct
                        # some device firmwares respond with a message received poacket before replying with the data
                        # example: 7e 1f 00 00 00 f9 52 01 00 00 53 7e (12 bytes, 0x7e bound. 10 bytes of data)
                        if ctrl_bytes == bytes([0xF9, 0x52]):
                            # logger.debug(f"{lp} inner_struct length: {len(inner_struct)} // {inner_struct.hex(' ')}")
                            if len(inner_struct) < 15:
                                if len(inner_struct) == 10:
                                    # server sent mesh info request, this seems to be the ack?
                                    # 7e 1f 00 00 00 f9 52 01 00 00 53 7e
                                    # checksum (idx 10) = idx 6 + idx 7 % 256
                                    # seen this with Full Color LED light strip controller firmware version: 3.0.204
                                    succ_idx = 6
                                    minfo_ack_succ = inner_struct[succ_idx]
                                    minfo_ack_chksum = inner_struct[9]
                                    calc_chksum = (inner_struct[5] + inner_struct[6]) % 256
                                    if minfo_ack_succ == 0x01:
                                        # logger.debug(f"{lp} Mesh info request ACK received, success: {minfo_ack_succ}."
                                        #              f" checksum byte = {minfo_ack_chksum}) // Calculated checksum "
                                        #              f"= {calc_chksum}")
                                        if minfo_ack_chksum != calc_chksum:
                                            logger.warning(
                                                f"{lp} Mesh info request ACK checksum failed! {minfo_ack_chksum} != {calc_chksum}"
                                            )

                                else:
                                    logger.debug(f"{lp} inner_struct is less than 15 bytes: {inner_struct.hex(' ')}")
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
                                            len(inner_struct),
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
                                                if loop_num == 1:
                                                    # byte 3 (idx 2) is a device type byte but,
                                                    # it only reports on the first item (itself)
                                                    # convert to int, and it is the same as deviceType from cloud.
                                                    if not self.id:
                                                        self.id = dev_id
                                                        self.lp = (
                                                            f"{self.address}[{self.id}]:"
                                                        )
                                                        cync_device = g.cync_lan.cfg_devices[dev_id]
                                                        logger.debug(f"{self.lp}parse:x{data[0]:02x}: setting HTTP"
                                                                     f"Device ID: {self.id}")
                                                        self.capabilities = cync_device.check_dev_capabilities(dev_type_id)
                                                        self.device_types = cync_device.check_dev_type(dev_type_id)
                                                        # logger.debug(f"{lp} device type ({dev_type_id}) capabilities: {self.capabilities}")
                                                        # logger.debug(f"{lp} device type ({dev_type_id}): {self.device_types}")
                                                        del cync_device
                                                    elif self.id and self.id != dev_id:
                                                        logger.warning(f"{lp} The first device reported in 0x83 is "
                                                                       f"usually the http device. current: {self.id} "
                                                                       f"// proposed: {dev_id}")
                                                    lp = f"{self.lp}parse:x{data[0]:02x}:"
                                                    self.device_type_id = dev_type_id

                                                ids_reported.append(dev_id)
                                                # structs.append(mesh_dev_struct.hex(" "))
                                                self.known_device_ids.append(dev_id)

                                            else:
                                                logger.warning(
                                                    f"{lp} Device ID {dev_id} not found in devices "
                                                    f"defined in config file: "
                                                    f"{g.cync_lan.server.devices.keys()}"
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
                                                f"{lp} parsing mesh info // {_m} // {_raw_m}"
                                            )
                                            for status in _m:
                                                await g.server.parse_status(
                                                    bytes(status)
                                                )

                                        mesh_info["status"] = _m
                                        mesh_info["id_from"] = self.id
                                        # logger.debug(f"\n\n{lp} MESH INFO // {_raw_m}\n")
                                        self.mesh_info = MeshInfo(**mesh_info)

                                    except IndexError:
                                        # ran out of data
                                        pass
                                    except Exception as e:
                                        logger.error(
                                            f"{lp} MESH INFO for loop EXCEPTION: {e}"
                                        )
                                    # Always clear parse mesh status
                                    self.parse_mesh_status = False
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
                        else:

                            logger.debug(
                                f"{lp} control bytes: {ctrl_bytes.hex(' ')} // packet data:  {packet_data.hex(' ')}") if CYNC_RAW else None
                            msg_cb_obj: Optional[MessageCallback] = None
                            # are any callbacks stored?
                            if self.messages.x73:
                                inner_msg_id = packet_data[1]
                                if inner_msg_id in self.messages.x73:
                                    # message id callbacks; the idea is to set device state on a successful callback
                                    # class has __eq__ method to compare id
                                    msg_idx = self.messages.x73.index(inner_msg_id)  # type: ignore
                                    msg_cb_obj = self.messages.x73.pop(msg_idx)
                                    logger.debug(
                                        f"{lp} Found a message callback for msg id: {inner_msg_id} -> "
                                        f"elapsed since sent: {time.time() - msg_cb_obj.sent_at} // "
                                        f"{repr(msg_cb_obj)}"
                                    )
                                else:
                                    logger.debug(f"{lp} no callback for msg_id: {inner_msg_id} ({self.messages.x73})")

                            if ctrl_bytes == bytes([0xF9, 0xD0]):
                                # control packet ack - changed state.
                                # handle callbacks for messages
                                # byte 8 is success? 0x01 yes // 0x00 no
                                # 7e 09 00 00 00 f9 d0 01 00 00 d1 7e
                                logger.debug(f"{lp} CONTROL packet ACK (ctrl_bytes = {ctrl_bytes}) "
                                             f"(inc_bytes = {packet_data[1:5]}) -> success: {packet_data[7]}")
                                if packet_data[7] == 0x01:
                                    if msg_cb_obj is not None:
                                        logger.debug(
                                            f"{lp} CALLING ASYNC CALLBACK -> {msg_cb_obj.args = } // "
                                            f"{msg_cb_obj.kwargs = } // {msg_cb_obj.callback = }"
                                        )
                                        await msg_cb_obj.callback(
                                            *msg_cb_obj.args, **msg_cb_obj.kwargs
                                        )
                                        # msg_cb_obj.args = []
                                        # msg_cb_obj.kwargs = {}
                                    else:
                                        # logger.debug(f"{lp} NO CALLBACK FOUND FOR CONTROL PACKET ACK ?")
                                        pass
                                else:
                                    logger.debug(f"{lp} CONTROL PACKET ACK -> FAILURE? success: {packet_data[7]}")

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
                f"{lp} sent UNKNOWN HEADER! Don't know how to respond!\n"
                f"RAW: {data}\nINT: {bytes2list(data)}\nHEX: {data.hex(' ')}"
            )

    async def ask_for_mesh_info(self, parse: bool = False):
        """
        Ask the device for mesh info. As far as I can tell, this will return whatever
        devices are connected to the device you are querying. It may also trigger
        the device to send its own status packet.
        """
        lp = self.lp
        # mesh_info = '73 00 00 00 18 2d e4 b5 d2 15 2c 00 7e 1f 00 00 00 f8 52 06 00 00 00 ff ff 00 00 56 7e'
        mesh_info_data = DEVICE_STRUCTS.requests.x73
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
        # logger.debug(f"{lp} Asking device for BT mesh info")
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
        logger.debug(f"{self.lp} Sending 0xa3 packet -> {a3_packet.hex(' ')}")
        await self.write(a3_packet)

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
        availability = b"online" if status else b"offline"
        # logger.debug(f"{lp} Publishing availability: {availability}")
        _ = await self.client.publish(
            f"{self.topic}/availability/{device_id}", availability, qos=QOS_0
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
                    "message": LWT_MSG,
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
            _ = await self.client.publish(
                f"{self.topic}/availability/{device_id}", availability, qos=QOS_0
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
        lp = f"{self.lp}parse status:"
        if device_id not in g.server.devices:
            # logger.error(
            #     f"{lp} Device ID {device_id} not found?! Have you deleted or added any devices recently? "
            #     f"You may need to re-export devices from your Cync account!"
            # )
            return
        power_status = "OFF" if device_status.state == 0 else "ON"
        mqtt_dev_state = {"state": power_status}

        device: CyncDevice = g.server.devices[device_id]
        if device.is_plug:
            # logger.debug(
            #     f"{lp} Converted HTTP status to MQTT switch => {self.topic}/status/{device_id}  {power_status}"
            # )
            _ = await self.client.publish(
                f"{self.topic}/status/{device_id}", power_status.encode(), qos=QOS_0
            )

        else:
            if device_status.brightness is not None:
                mqtt_dev_state["brightness"] = device_status.brightness

            if device.supports_rgb and device_status.temperature is not None:
                if (
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
                    # RGBW
                    # how to write device_status.temperature is greater than 0 <= 100 ?
                elif device.supports_temperature and (
                    0 <= device_status.temperature <= 100
                ):
                    mqtt_dev_state["color_mode"] = "color_temp"
                    mqtt_dev_state["color_temp"] = self.tlct_to_hassct(
                        device_status.temperature
                    )

            # White tunable (non rgb light)
            elif device.supports_temperature and device_status.temperature is not None:
                mqtt_dev_state["color_mode"] = "color_temp"
                mqtt_dev_state["color_temp"] = self.tlct_to_hassct(
                    device_status.temperature
                )

            # logger.debug(
            #     f"{lp} Converting HTTP status to MQTT => {self.topic}/status/{device_id} "
            #     + json.dumps(mqtt_dev_state)
            # )
            try:
                await asyncio.wait_for(
                    self.client.publish(
                        f"{self.topic}/status/{device_id}",
                        json.dumps(mqtt_dev_state).encode(),
                        qos=QOS_0,
                    ),
                    timeout=3.0,
                )
            except asyncio.TimeoutError:
                logger.error(f"{lp} Timeout waiting for MQTT publish")
            except Exception as e:
                logger.error(f"{lp} publish exception: {e}")

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
                            device_id = int(topic[2])
                            if device_id not in g.server.devices:
                                logger.warning(
                                    f"{lp} Device ID {device_id} not found, have you deleted or added any "
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

                                if "state" in json_data and (
                                    "brightness" not in json_data
                                    or device.brightness < 1
                                ):
                                    if json_data["state"].upper() == "ON":
                                        logger.debug(f"{lp} setting power to ON")
                                        await device.set_power(1)
                                    else:
                                        logger.debug(f"{lp} setting power to OFF")
                                        await device.set_power(0)
                                if "brightness" in json_data:
                                    lum = int(json_data["brightness"])
                                    logger.debug(f"{lp} setting brightness to: {lum}")
                                    if 5 > lum > 0:
                                        lum = 5
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
                                if "color" in json_data:
                                    color = []
                                    for rgb in ("r", "g", "b"):
                                        if rgb in json_data["color"]:
                                            color.append(int(json_data["color"][rgb]))
                                        else:
                                            color.append(0)
                                    logger.debug(f"{lp} setting RGB to: {color}")
                                    await device.set_rgb(*color)
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
                        await asyncio.sleep(0.1)

                    elif len(topic) == 2:
                        if topic[1] == "shutdown":
                            logger.info(
                                "sub worker - Shutdown requested, sending SIGTERM"
                            )
                            os.kill(os.getpid(), signal.SIGTERM)
                        elif topic[1] == "devices" and payload.lower() == b"get":
                            await self.publish_devices()
                        elif topic[0] == self.ha_topic and topic[1] == "status":

                            if payload.upper() == b"ONLINE":
                                logger.info(
                                    f"{lp} HASS is signaling online, re-announce devices"
                                )
                                await self.homeassistant_discovery()
                                await asyncio.sleep(1)

                                for device_id, device in g.server.devices.items():
                                    availability = device.online
                                    await self.pub_online(device_id, availability)
                            elif payload.upper() == b"OFFLINE":
                                logger.info(f"{lp} HASS is signaling offline!")

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
            device_config = {
                "name": device.name,
                "id": device.id,
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
            try:
                logger.debug(
                    f"{lp} {self.ha_topic}/devices/{device.id}  "
                    + json.dumps(device_config)
                )
                _ = await self.client.publish(
                    f"{self.ha_topic}/devices/{device.id}",
                    json.dumps(device_config).encode(),
                    qos=QOS_1,
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
            for device_id, device in g.server.devices.items():
                unique_id = device.mac.replace(":", "")
                origin_struct = {
                    "name": "cync-lan",
                    "sw_version": CYNC_VERSION,
                    "support_url": REPO_URL,
                }
                obj_id = f"cync_lan_{device.name}"
                if device.is_plug:
                    switch_cfg = {
                        "object_id": obj_id,
                        "name": device.name,
                        "command_topic": "{0}/set/{1}".format(self.topic, device_id),
                        "state_topic": "{0}/status/{1}".format(self.topic, device_id),
                        "avty_t": "{0}/availability/{1}".format(self.topic, device_id),
                        "pl_avail": "online",
                        "pl_not_avail": "offline",
                        "unique_id": unique_id,
                        "origin": origin_struct,
                    }
                    # logger.debug(
                    #     f"{lp} {self.ha_topic}/switch/{device_id}/config  "
                    #     + json.dumps(switch_cfg)
                    # )
                    try:
                        _ = await self.client.publish(
                            f"{self.ha_topic}/switch/{device_id}/config",
                            json.dumps(switch_cfg).encode(),
                            qos=QOS_1,
                        )
                    except Exception as e:
                        logger.error(
                            "homeassistant discovery - Unable to publish mqtt message => %s"
                            % e
                        )

                else:
                    try:
                        light_config = {
                            "object_id": obj_id,
                            "name": device.name,
                            "command_topic": "{0}/set/{1}".format(
                                self.topic, device_id
                            ),
                            "state_topic": "{0}/status/{1}".format(
                                self.topic, device_id
                            ),
                            "avty_t": "{0}/availability/{1}".format(
                                self.topic, device_id
                            ),
                            "pl_avail": "online",
                            "pl_not_avail": "offline",
                            "unique_id": unique_id,
                            "schema": "json",
                            "brightness": True,
                            "brightness_scale": 100,
                            "origin": origin_struct,
                        }
                        if device.supports_temperature or device.supports_rgb:
                            # hass has deprecated color-mode in device config
                            # light_config["color_mode"] = True
                            light_config["supported_color_modes"] = []
                            if device.supports_temperature:
                                light_config["supported_color_modes"].append(
                                    "color_temp"
                                )
                                light_config["max_mireds"] = self.hass_maxct
                                light_config["min_mireds"] = self.hass_minct
                            if device.supports_rgb:
                                light_config["supported_color_modes"].append("rgb")

                        # logger.debug(
                        #     f"{lp} {self.ha_topic}/light/{device_id}/config  "
                        #     + json.dumps(light_config)
                        # )
                        _ = await self.client.publish(
                            f"{self.ha_topic}/light/{device_id}/config",
                            json.dumps(light_config).encode(),
                            qos=QOS_1,
                        )
                    except Exception as e:
                        logger.error(
                            "%s - Unable to publish mqtt message... skipped -> %s"
                            % (lp, e)
                        )
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
        email: Optional[str] = cli_args.email
        code: Optional[str] = cli_args.code
        save_auth: bool = cli_args.save_auth
        auth_output: Optional[Path] = cli_args.auth_file
        auth_file: Optional[Path] = cli_args.auth_file
        access_token = None
        token_user = None

        try:
            if not auth_file:
                access_token, token_user = cloud_api.authenticate_2fa(email, code)
            else:
                raw_file_yaml = yaml.safe_load(auth_file.read_text())
                access_token = raw_file_yaml["token"]
                token_user = raw_file_yaml["user"]
            if not access_token or not token_user:
                raise ValueError(
                    "main: Failed to authenticate, no token or user found. Check auth file or email/OTP"
                )

            logger.info(
                f"main: Cync Cloud API auth data => user_id: {token_user} // token: {access_token}"
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
