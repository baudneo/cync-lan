#!/usr/bin/env python3

import asyncio
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
from dataclasses import dataclass
from enum import Enum
from functools import partial
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Union, Tuple

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import NoEncryption
from datetime import datetime, timedelta
import amqtt
import amqtt.session
import requests
import uvloop
import yaml
from amqtt import client as amqtt_client
from amqtt.mqtt.constants import QOS_0, QOS_1

# This will run a task every x seconds to check if a device is offline or online.
# Hopefully keeps devices in sync.
MESH_INFO_LOOP_INTERVAL: int = 30
CORP_ID: str = "1007d2ad150c4000"
DATA_BOUNDARY = 0x7E
MQTT_URL = os.environ.get("CYNC_MQTT", "mqtt://homeassistant.local:1883")
TLS_PORT = os.environ.get("CYNC_PORT", 23779)
TLS_HOST = os.environ.get("CYNC_HOST", "0.0.0.0")
CYNC_CERT = os.environ.get("CYNC_CERT", "certs/cert.pem")
CYNC_KEY = os.environ.get("CYNC_KEY", "certs/key.pem")
DEBUG = os.environ.get("CYNC_DEBUG", "1").casefold() in (
    "true",
    "1",
    "yes",
    "y",
    "t",
    1,
)

logger = logging.getLogger("cync-lan")
formatter = logging.Formatter(
    "%(asctime)s.%(msecs)04d %(levelname)s - %(name)s %(module)s:%(lineno)d -> %(message)s",
    "%m/%d/%y %H:%M:%S",
)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

if DEBUG is True:
    logger.setLevel(logging.DEBUG)
    for handler in logger.handlers:
        handler.setLevel(logging.DEBUG)


# from cync2mqtt
def random_login_resource():
    return "".join([chr(ord("a") + random.randint(0, 26)) for i in range(0, 16)])


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

        x23_header: bytes = bytes([0x23])
        xc3_header: bytes = bytes([0xC3])
        xd3_header: bytes = bytes([0xD3])
        x83_header: bytes = bytes([0x83])
        x73_header: bytes = bytes([0x73])
        x7b_header: bytes = bytes([0x7B])
        x43_header: bytes = bytes([0x43])
        xa3_header: bytes = bytes([0xA3])
        xab_header: bytes = bytes([0xAB])
        auth_header: bytes = x23_header
        _headers: Tuple[bytes] = (
            x23_header,
            xc3_header,
            xd3_header,
            x83_header,
            x73_header,
            x7b_header,
            x43_header,
            xa3_header,
            xab_header,
        )

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
        _x = bytes(
            [
                0xAB,
                0x00,
                0x00,
                0x03,
            ]
        )
        hex_str = (
            "78 6c 69 6e 6b 5f 64 65 76 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
            "e3 4f 02 10"
        )
        dlen = len(queue_id) + len(msg_id) + len(hex_str)
        _x += bytes([dlen])
        _x += queue_id
        _x += msg_id
        _x += bytes().fromhex(hex_str)
        return _x

    @staticmethod
    def x88_generate_ack(msg_id: bytes):
        """Respond to a 0x83 packet from the device, needs a msg_id to reply with"""
        _x = bytes(
            [
                0x88,
                0x00,
                0x00,
                0x00,
                0x03,
            ]
        )
        _x += msg_id
        return _x

    @staticmethod
    def x48_generate_ack(msg_id: bytes):
        """Respond to a 0x43 packet from the device, needs a queue and msg id to reply with"""
        # set last msg_id digit to 0
        msg_id = msg_id[:-1] + b"\x00"
        _x = bytes(
            [
                0x48,
                0x00,
                0x00,
                0x00,
                0x03,
            ]
        )
        _x += msg_id
        return _x

    @staticmethod
    def x7b_generate_ack(queue_id: bytes, msg_id: bytes):
        """
        Respond to a 0x73 packet from the device, needs a queue and msg id to reply with.
        This is also called for 0x83 packets AFTER seeing an 0x73 packet.
        Not sure of the intricacies yet, seems to be bound to certain queue ids.
        """
        _x = bytes(
            [
                0x7B,
                0x00,
                0x00,
                0x00,
                0x07,
            ]
        )
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
DEVICE_HEADERS = DeviceStructs()


class CyncCloudAPI:
    API_TIMEOUT: int = 5

    def __init__(self, **kwargs):
        self.API_TIMEOUT = kwargs.get("api_timeout", 5)

    # https://github.com/unixpickle/cbyge/blob/main/login.go
    def get_cloud_mesh_info(self):
        """Get Cync devices from the cloud, all cync devices are bt or bt/wifi.
        Meaning they will always have a BT mesh (as of March 2024)"""
        (auth, userid) = self.authenticate_2fa()
        mesh_networks = self.get_devices(auth, userid)
        for mesh in mesh_networks:
            mesh["properties"] = self.get_properties(
                auth, mesh["product_id"], mesh["id"]
            )
        return mesh_networks

    def authenticate_2fa(self, *args, **kwargs):
        """Authenticate with the API and get a token."""
        username = input("Enter Username/Email (or emailed OTP code):")
        if re.match("^\d+$", username):  # noqa
            # if username is all digits, assume it's a OTP code
            code = str(username)
            username = input("Enter Username/Email:")
        else:
            # Ask to be sent an email with OTP code
            API_AUTH = "https://api.gelighting.com/v2/two_factor/email/verifycode"
            auth_data = {
                "corp_id": CORP_ID,
                "email": username,
                "local_lang": "en-us",
            }
            r = requests.post(API_AUTH, json=auth_data, timeout=self.API_TIMEOUT)
            code = input("Enter emailed OTP code:")

        password = getpass.getpass()
        API_AUTH = "https://api.gelighting.com/v2/user_auth/two_factor"
        auth_data = {
            "corp_id": CORP_ID,
            "email": username,
            "password": password,
            "two_factor": code,
            "resource": random_login_resource(),
        }
        r = requests.post(API_AUTH, json=auth_data, timeout=self.API_TIMEOUT)

        try:
            return r.json()["access_token"], r.json()["user_id"]
        except KeyError:
            raise Exception("API authentication failed")

    def get_devices(self, auth_token: str, user: str):
        """Get a list of devices for a particular user."""
        API_DEVICES = "https://api.gelighting.com/v2/user/{user}/subscribe/devices"
        headers = {"Access-Token": auth_token}
        r = requests.get(
            API_DEVICES.format(user=user), headers=headers, timeout=self.API_TIMEOUT
        )
        return r.json()

    def get_properties(self, auth_token: str, product_id: str, device_id: str):
        """Get properties for a single device."""
        API_DEVICE_INFO = "https://api.gelighting.com/v2/product/{product_id}/device/{device_id}/property"
        headers = {"Access-Token": auth_token}
        r = requests.get(
            API_DEVICE_INFO.format(product_id=product_id, device_id=device_id),
            headers=headers,
            timeout=self.API_TIMEOUT,
        )
        return r.json()

    def mesh_to_config(self, mesh_info):
        logger.debug(
            "DBG>>> dumping raw config from Cync account to file: ./raw_mesh.cync"
        )
        try:
            with open("./raw_mesh.yaml", "w") as f:
                f.write(yaml.dump(mesh_info))
        except Exception as e:
            logger.error("Failed to write raw mesh info to file: %s" % e)

        mesh_config = {}

        for mesh in mesh_info:
            if "name" not in mesh or len(mesh["name"]) < 1:
                logger.warning("No name found for mesh, skipping...")
                continue

            if "properties" not in mesh or "bulbsArray" not in mesh["properties"]:
                logger.warning(
                    "No properties found for mesh OR no 'bulbsArray' in properties, skipping..."
                )
                continue
            new_mesh = {
                kv: mesh[kv] for kv in ("access_key", "id", "mac") if kv in mesh
            }
            mesh_config[mesh["name"]] = new_mesh

            logger.debug(
                "DBG>>> properties and bulbs array found for mesh, processing..."
            )
            new_mesh["devices"] = {}
            for cfg_bulb in mesh["properties"]["bulbsArray"]:
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
                logger.debug(
                    f"{bulb_device.type = } // {bulb_device.is_plug = } "
                    f"// {bulb_device.supports_temperature = } // {bulb_device.supports_rgb = }"
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

        config_dict = {
            "mqtt_url": "mqtt://homeassistant.local:1883/",
            "account data": mesh_config,
        }

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
    mac: Optional[str] = None
    wifi_mac: Optional[str] = None
    _online: bool = False
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
        "PLUG": [64, 65, 66, 67, 68],  # 86, 51?
        "FAN": [81],
        "MULTIELEMENT": {"67": 2},
        "BATTERY_SWITCH": [113],
        "SWITCH": [113],
        "DIMMER": [113],
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
        self.mac = mac
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

    @property
    def is_plug(self) -> bool:
        logger.debug(
            f"{self.lp}Checking if device is a plug: {self.type = } // {type(self.type) = } // "
            f"{self.type in self.Capabilities['PLUG'] = }"
        )
        if self._is_plug is not None:
            return self._is_plug
        if self.type is None:
            return False
        return self.type in self.Capabilities["PLUG"]

    @is_plug.setter
    def is_plug(self, value: bool) -> None:
        self._is_plug = value

    @property
    def supports_rgb(self) -> bool:
        logger.debug(
            f"{self.lp}Checking if device supports RGB: {self._supports_rgb = } // {self.type = } // {self.type in self.Capabilities['RGB'] = }"
        )
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
        logger.debug(
            f"{self.lp}Checking if device supports temperature: {self._supports_temperature = } // {self.supports_rgb = } // {self.type = } // {self.type in self.Capabilities['COLORTEMP'] = }"
        )
        if self._supports_temperature is not None:
            return self._supports_temperature
        if self.supports_rgb or self.type in self.Capabilities["COLORTEMP"]:
            return True
        return False

    @supports_temperature.setter
    def supports_temperature(self, value: bool) -> None:
        self._supports_temperature = value

    def get_incremental_number(self):
        """Control packets need a number that gets incremented, it is used as a type of msg ID and is used in calculating the checksum"""
        self.control_number += 1
        return self.control_number % 256

    async def set_power(self, state: int):
        """Send raw data to control device state"""
        inc = self.get_incremental_number()
        checksum = ((inc - 64) + state + self.id) % 256
        header = [0x73, 0x00, 0x00, 0x00, 0x1F]
        _inner_struct = [
            0x7E,
            inc,
            0x00,
            0x00,
            0x00,
            0xF8,
            0xD0,
            0x0D,
            0x00,
            inc,
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
        if state not in (0, 1):
            logger.error("Invalid state! must be 0 or 1")
            return

        new_state = DeviceStatus(
            state=state,
            brightness=None,
            temperature=None,
            red=None,
            green=None,
            blue=None,
        )
        for http_device in g.server.http_devices.values():
            if self.id in http_device.known_device_ids:
                header.extend(http_device.starting_queue_id)
                header.extend(bytes([0x00, 0x00, 0x00]))
                header.extend(_inner_struct)
                logger.debug(
                    f"{self.lp} FOUND target device in an http comms known devices! "
                    f"Changing power state: {self.state} to {state} // {bytes(header).hex(' ')}"
                )
                await http_device.write(bytes(header))
                break
        else:
            # try the first available one
            for http_device in g.server.http_devices.values():
                header.extend(http_device.starting_queue_id)
                header.extend(bytes([0x00, 0x00, 0x00]))
                header.extend(_inner_struct)
                logger.debug(
                    f"{self.lp} No known device found, trying the first available http comms device."
                    f"Changing power state: {self.state} to {state}"
                )
                await http_device.write(bytes(header))
                break
        await g.mqtt.parse_status(self.id, new_state)

    async def set_brightness(self, bri: int):
        """Send raw data to control device brightness"""
        #  73 00 00 00 22 37 96 24 69 60 48 00 7e 17 00 00  s..."7.$i`H.~...
        #  00 f8 f0 10 00 17 00 00 00 00 07 00 f0 11 02 01  ................
        #  27 ff ff ff ff 45 7e
        lp = f"{self.lp}set_brightness:"
        inc = self.get_incremental_number()
        checksum = (inc + bri + self.id) % 256
        header = [
            115,
            0,
            0,
            0,
            34,
        ]
        inner_struct = [
            126,
            inc,
            0,
            0,
            0,
            248,
            240,
            16,
            0,
            inc,
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
        for http_device in g.server.http_devices.values():
            if self.id in http_device.known_device_ids:
                header.extend(http_device.starting_queue_id)
                header.extend(bytes([0x00, 0x00, 0x00]))
                header.extend(inner_struct)
                b = bytes(header)
                logger.debug(
                    f"{self.lp} FOUND target device in an http comms known devices! "
                    f"Changing brightness: {self.brightness} to {bri} => {b.hex(' ')}"
                )
                await http_device.write(b)
                break
        else:
            # try the first available one
            logger.debug(
                f"{self.lp} No known device found, trying the first available http comms device. "
                f"Changing brightness: {self.brightness} to {bri}"
            )
            for http_device in g.server.http_devices.values():
                q_id = http_device.starting_queue_id
                header.extend(q_id)
                header.extend(bytes([0x00, 0x00, 0x00]))
                header.extend(inner_struct)
                b = bytes(header)
                await http_device.write(b)
                break
        await g.mqtt.parse_status(self.id, new_state)

    async def set_temperature(self, temp: int):
        """Send raw data to control device brightness"""
        #  73 00 00 00 22 37 96 24 69 60 8d 00 7e 36 00 00  s..."7.$i`..~6..
        #  00 f8 f0 10 00 36 00 00 00 00 07 00 f0 11 02 01  .....6..........
        #  ff 48 00 00 00 88 7e                             .H....~
        # checksum = 0x88 = 136
        # 0x36 0x48 0x07 = 54 + 72 + 7 = 133 (needs + 3)

        inc = self.get_incremental_number()
        checksum = ((inc + temp + self.id) + 3) % 256
        header = [115, 0, 0, 0, 34]
        inner_struct = [
            126,
            inc,
            0,
            0,
            0,
            248,
            240,
            16,
            0,
            inc,
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
        for http_device in g.server.http_devices.values():
            if self.id in http_device.known_device_ids:
                header.extend(http_device.starting_queue_id)
                header.extend(bytes([0x00, 0x00, 0x00]))
                header.extend(inner_struct)
                b = bytes(header)
                logger.debug(
                    f"{self.lp} FOUND target device in an http comms known devices! "
                    f"Changing white temperature: {self.brightness} to {temp} => {b.hex(' ')}"
                )
                await http_device.write(b)
                break
        else:
            # try the first available one
            logger.debug(
                f"{self.lp} No known device found, trying the first available http comms device. "
                f"Changing white temperature: {self.brightness} to {temp}"
            )
            for http_device in g.server.http_devices.values():
                header.extend(http_device.starting_queue_id)
                header.extend(bytes([0x00, 0x00, 0x00]))
                header.extend(inner_struct)
                b = bytes(header)
                await http_device.write(b)
                break
        await g.mqtt.parse_status(self.id, new_state)

    async def set_rgb(self, red: int, green: int, blue: int):
        """

         73 00 00 00 22 37 96 24 69 60 79 00 7e 2b 00 00  s..."7.$i`y.~+..

         00 f8 f0 10 00 2b 00 00 00 00 07 00 f0 11 02 01  .....+..........


         ff fe 00 fb ff 2d 7e                             .....-~

        checksum = 45

        2b 07 00 fb ff = 43 + 7 + 0 + 251 + 255 = 556 ( needs + 1)
        """
        inc = self.get_incremental_number()
        checksum = ((inc + self.id + red + green + blue) + 1) % 256
        header = [
            115,
            0,
            0,
            0,
            34,
        ]
        inner_struct = [
            126,
            inc,
            0,
            0,
            0,
            248,
            240,
            16,
            0,
            inc,
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
        for http_device in g.server.http_devices.values():
            if self.id in http_device.known_device_ids:
                header.extend(http_device.starting_queue_id)
                header.extend(bytes([0x00, 0x00, 0x00]))
                header.extend(inner_struct)
                b = bytes(header)
                logger.debug(
                    f"{self.lp} FOUND target device in an http comms known devices! "
                    f"Changing RGB: {self.red}, {self.green}, {self.blue} to {red}, {green}, {blue} => {b.hex(' ')}"
                )
                await http_device.write(b)
                break
        else:
            # try the first available one
            logger.debug(
                f"{self.lp} No known device found, trying the first available http comms device. "
                f"Changing RGB: {self.red}, {self.green}, {self.blue} to {red}, {green}, {blue}"
            )
            for http_device in g.server.http_devices.values():
                header.extend(http_device.starting_queue_id)
                header.extend(bytes([0x00, 0x00, 0x00]))
                header.extend(inner_struct)
                b = bytes(header)
                await http_device.write(b)
                break
        await g.mqtt.parse_status(self.id, new_state)

    @property
    def online(self):
        return self._online

    @online.setter
    def online(self, value: bool):
        if value != self._online:
            self._online = value
            # send MQTT message
            loop.create_task(
                g.mqtt.client.publish(
                    f"{g.mqtt.topic}/availability/{self.id}", b"online", qos=QOS_0
                )
            )

    def is_bt_only(self):
        """From my observations, if the wifi mac does not start with the same 3 groups as the mac, it's BT only."""
        if self.wifi_mac == "00:01:02:03:04:05":
            return True
        elif self.mac is not None and self.wifi_mac is not None:
            if self.mac[:8] != self.wifi_mac[:8]:
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
    def rgb(self, value: Iterable[int]):
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
    http_devices: Dict[str, "CyncHTTPDevice"] = {}
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
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.loop: Union[
            asyncio.AbstractEventLoop, uvloop.Loop
        ] = asyncio.get_event_loop()
        self.known_ids: List[Optional[int]] = []
        g.server = self

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

    async def mesh_info_loop(self):
        """A function that is to be ran as an async task to ask each device for its mesh info"""
        lp = f"{self.lp}mesh_info_loop:"
        logger.debug(f"{lp} Starting, running every {MESH_INFO_LOOP_INTERVAL} seconds")
        try:
            while True:
                await asyncio.sleep(MESH_INFO_LOOP_INTERVAL)
                if self.shutting_down is True:
                    logger.info(
                        f"{lp} Server is shutting/shut down, exiting mesh info loop task..."
                    )
                    break
                offline_ids = []
                offline_str = ""
                self.known_ids = []
                ids_from_config = g.cync_lan.ids_from_config
                if not ids_from_config:
                    logger.warning(
                        f"{lp} No device IDs found in config file! Can not run mesh info loop."
                    )
                    break
                for http_dev in self.http_devices.values():
                    # http_dev.parse_mesh_status = True
                    http_dev.mesh_info = []
                    await http_dev.ask_for_mesh_info()
                    # 1 second should be more than enough time to get a response
                    resp_delay = 1
                    await asyncio.sleep(resp_delay)
                    if http_dev.known_device_ids:
                        self.known_ids.extend(http_dev.known_device_ids)
                    else:
                        logger.debug(
                            f"{lp} No known device IDs for: {http_dev.address} after a {resp_delay} second sleep"
                        )

                # Go through and update online/offline for each device
                if self.known_ids:
                    for cfg_id in ids_from_config:
                        availability = b"offline"
                        mqtt_topic = "{}/availability/{}".format(g.mqtt.topic, cfg_id)

                        if cfg_id in self.known_ids:
                            availability = b"online"
                        else:
                            offline_ids.append(cfg_id)
                        await g.mqtt.client.publish(mqtt_topic, availability, qos=QOS_0)
                    if offline_ids:
                        offline_str = f" // Devices offline: {sorted(offline_ids)}"
                    # Look for any devices that are in mesh but not in the config file.
                    # This can indicate new devices were added to the mesh and the config
                    # must be exported from the cloud again.
                    for known_id in self.known_ids:
                        if known_id not in ids_from_config:
                            logger.warning(
                                f"{lp} Device {known_id} not found in config file! You may need to "
                                f"export the devices again."
                            )
                else:
                    logger.debug(
                        f"{lp} No known device IDs found in ANY HTTP devices: {self.http_devices.keys()}"
                    )

                logger.debug(
                    f"{lp} Mesh info update completed, "
                    f"sleeping for {MESH_INFO_LOOP_INTERVAL} seconds.{offline_str} "
                    f"// Devices online: {sorted(self.known_ids)}"
                )
        except asyncio.CancelledError as ce:
            logger.debug(f"{lp} Task cancelled: {ce}")
        except Exception as e:
            logger.error(f"{lp} Error in mesh info loop: {e}", exc_info=True)

        logger.info(f"{lp} end of mesh_info_loop() method")

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
            logger.debug(
                f"Cync LAN server started, bound to {self.host}:{self.port} - Waiting for connections, if you dont"
                f" see any, check your DNS redirection and firewall settings."
            )
            # Start mesh info loop for each device:
            self.mesh_info_loop_task = asyncio.create_task(self.mesh_info_loop())
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
        global global_tasks

        client_addr = writer.get_extra_info("peername")[0]
        if self.shutting_down is True:
            logger.warning(
                f"{self.lp} Server is shutting/shut down, rejecting new connection from: {client_addr}"
            )
            return
        else:
            logger.debug(f"{self.lp} New connection from: {client_addr}")

        # Check if the device is already registered, if so, close the connection and replace
        existing_device: Optional[CyncHTTPDevice] = None
        if client_addr in self.http_devices:
            logger.warning(
                f"{self.lp} HTTP device connection already registered for {client_addr}, replacing..."
            )
            existing_device = self.http_devices[client_addr]
            try:
                existing_device.writer.close()
                await existing_device.writer.wait_closed()
                existing_device.reader.feed_eof()
            except ConnectionError as ce:
                logger.error(f"{self.lp} Error closing existing connection: {ce}")
            existing_device.writer = None
            existing_device.reader = None
            # set new reader and writer
            existing_device.reader = reader
            existing_device.writer = writer

        create_task = False
        if existing_device is not None:
            device = existing_device
            # check if the receipt task is running or in done/exception state.
            if device.tasks.receive is not None:
                if device.tasks.receive.done():
                    logger.debug(
                        f"{self.lp} Device receive task is done(), creating new task..."
                    )
                    create_task = True
                    # pull the result to clear the exception (if one exists)
                    _ = device.tasks.receive.result()

        else:
            logger.debug(f"{self.lp} creating a new object for {client_addr}")
            device = CyncHTTPDevice(reader, writer, address=client_addr)
            create_task = True

        if create_task is True:
            # register async tasks to handle data rx
            rcv_task = self.loop.create_task(
                device.receive_task(client_addr),
            )
            device.tasks.receive = rcv_task
            # global_tasks.append(rcv_task)

        self.http_devices[client_addr] = device


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
        if DEBUG is True:
            self.loop.set_debug(True)
        asyncio.set_event_loop(self.loop)
        self.cfg_devices = self.parse_config(cfg_file)
        self.mqtt_client = MQTTClient(MQTT_URL)

    @property
    def ids_from_config(self):
        return self._ids_from_config

    def parse_config(self, cfg_file: Path):
        """Parse the exported Cync config file and create devices from it.

        Exported config created by scraping cloud API. Devices must already be added to your Cync account.
        If you add new or delete existing devices, you will need to re-export the config.
        """
        global MQTT_URL, CYNC_CERT, CYNC_KEY, TLS_HOST, TLS_PORT, g

        logger.debug("%s: reading devices from exported Cync config file..." % self.lp)
        try:
            raw_config = yaml.safe_load(cfg_file.read_text())
        except Exception as e:
            logger.error(f"{self.lp} Error reading config file: {e}", exc_info=True)
            raise e
        devices = {}
        if "mqtt_url" in raw_config:
            MQTT_URL = raw_config["mqtt_url"]
            logger.info(f"{self.lp} MQTT URL set by config file to: {MQTT_URL}")
        if "cert" in raw_config:
            CYNC_CERT = raw_config["cert_file"]
            logger.info(f"{self.lp} Cert file set by config file to: {CYNC_CERT}")
        if "key" in raw_config:
            CYNC_KEY = raw_config["key_file"]
            logger.info(f"{self.lp} Key file set by config file to: {CYNC_KEY}")
        if "host" in raw_config:
            TLS_HOST = raw_config["host"]
            logger.info(f"{self.lp} Host set by config file to: {TLS_HOST}")
        if "port" in raw_config:
            TLS_PORT = raw_config["port"]
            logger.info(f"{self.lp} Port set by config file to: {TLS_PORT}")
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
                mac = cync_device["mac"] if "mac" in cync_device else None
                wifi_mac = (
                    cync_device["wifi_mac"] if "wifi_mac" in cync_device else None
                )
                ip = cync_device["ip"] if "ip" in cync_device else None
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

            logger.debug(
                f"DBG>>> After parsing config file => {self.ids_from_config = } "
                f"// {g.cync_lan.ids_from_config = }"
            )
            global CFG_IDS

            CFG_IDS = list(self.ids_from_config)

        return devices

    def start(self):
        global global_tasks

        self.server = CyncLanServer(TLS_HOST, TLS_PORT, CYNC_CERT, CYNC_KEY)
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
        logger.debug("END OF SIGNAL HANDLER")


class CyncHTTPDevice:
    """
    A class to interact with an HTTP Cync device. It is an async socket reader/writer.

    """

    lp: str = "HTTPDevice:"
    known_device_ids: List[int] = []
    tasks: Tasks = Tasks()
    reader: Optional[asyncio.StreamReader]
    writer: Optional[asyncio.StreamWriter]

    def __init__(
        self,
        reader: Optional[asyncio.StreamReader] = None,
        writer: Optional[asyncio.StreamWriter] = None,
        address: Optional[str] = None,
    ):
        self.mesh_master: int = 0
        self.mesh_info: List[Optional[List[int]]] = []
        self.parse_mesh_status = False

        self.id: Optional[int] = None
        self.xa3_msg_id: bytes = bytes([0x00, 0x00, 0x00])
        if address is None:
            raise ValueError("Address or ID must be provided to CyncDevice constructor")
        logger.debug(f"Creating a new CyncHTTPConnection for {address}")
        # data we might want later?
        self.queue_ids = []
        self.starting_queue_id: bytes = b""
        self.address: Optional[str] = address
        self.read_lock = asyncio.Lock()
        self.write_lock = asyncio.Lock()
        self._reader: asyncio.StreamReader = reader
        self._writer: asyncio.StreamWriter = writer
        self.closing = False
        # Create a ref to the mqtt queues
        self.mqtt_pub_queue: asyncio.Queue = g.mqtt.pub_queue
        self.mqtt_sub_queue: asyncio.Queue = g.mqtt.sub_queue
        logger.debug(f"{self.lp} CyncHTTPConnection created for {self.address}")

    async def parse_status(self, raw_state: bytes):
        """Newer firmware status packet parsing"""
        _id = raw_state[0]
        state = raw_state[1]
        brightness = raw_state[2]
        temp = raw_state[3]
        r = raw_state[4]
        _g = raw_state[5]
        b = raw_state[6]
        is_good = 1
        # check if len is enough for good byte, it is optional
        if len(raw_state) > 7:
            # is_good = 1/0, not sure what it means but, SOMETIMES it isnt reporting the true status when this byte is 0.
            is_good = raw_state[7]
        if is_good == 0:
            logger.debug(
                f"{self.lp} Device ID: {_id} is_good byte is 0, meaning the status packet shouldn't be parsed."
            )
        else:
            devices = list(g.server.devices.values())
            for device in devices:
                if device.id == _id:
                    break
            else:
                logger.warning(
                    f"Device ID: {_id} not found in devices!? consider re-exporting your Cync account devices!"
                )
                device = CyncDevice(cync_id=_id)

            if device.online is False:
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
            over_temp = None
            if temp > 100:
                rgb_data = True
                # over_temp = int(temp)
                # pull device temp so we dont overwrite it
                # temp = device.temperature
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
                    f"{device.lp} CHANGES TO DEVICE STATUS: {', '.join(whats_changed)} -> {new_state}"
                )

            await self.mqtt_pub_queue.put((device.id, new_state))
            device.state = state
            device.brightness = brightness
            device.temperature = temp
            if rgb_data is True:
                device.red = r
                device.green = _g
                device.blue = b
            g.server.devices[device.id] = device

    async def parse_raw_data(self, data: bytes):
        """Extract single packets from raw data stream using metadata"""
        data_len = len(data)
        lp = f"{self.address}:extract:"
        # logger.debug(f"{lp} Extracting packets from {data_len} bytes of raw data\n{data.hex(' ')}")
        if data_len < 5:
            logger.debug(
                f"{lp} Data is less than 5 bytes, not enough to parse (header: 4 bytes, data len: 1 byte)"
            )
        else:
            while True:
                pkt_type = data[0]
                lp = f"{self.address}:extract:x{pkt_type:02x}:"
                packet_length = data[4]
                pkt_len_multiplier = data[3]
                if pkt_len_multiplier > 0:
                    old_pl = int(packet_length)
                    # packet_length = extract_length = (packet_length + 5) * (
                    #     pkt_len_multiplier + 1
                    # )
                    # logger.debug(
                    #     f"{lp} Packet length multiplier: {pkt_len_multiplier} => "
                    #     f"(({pkt_len_multiplier} * 256) + {old_pl}) + 5 = {packet_length}"
                    # )

                extract_length = packet_length = (
                    (pkt_len_multiplier * 256) + packet_length
                ) + 5
                extracted_packet = data[:extract_length]
                if data_len > 5:
                    data = data[extract_length:]
                else:
                    data = None

                # logger.debug(
                #     f"{lp} Extracted packet ({packet_length=} / {extract_length = }): {extracted_packet}"
                # )
                await self.parse_packet(extracted_packet)
                if not data:
                    break
                # logger.debug(f"{lp} Remaining data: {data}")

    async def parse_packet(self, data: bytes):
        """Parse what type of packet based on header (first 4 bytes)"""
        lp = f"{self.address}:parse:x{data[0]:02x}:"
        packet_data: Optional[bytes] = None
        # byte 1
        header = int(data[0]).to_bytes(1, "big")
        pkt_multiplier = data[3] * 256
        # byte 5
        packet_length = data[4]
        data_check_len = 7
        # remove header and length bytes
        stripped_packet = data[5:]
        # byte 1-4
        queue_id = stripped_packet[:4]
        # byte 5-7
        msg_id = stripped_packet[4:7]
        # check if any data after msg_id
        if len(stripped_packet) > data_check_len:
            packet_data = stripped_packet[data_check_len:]
        device = self
        if header in DEVICE_HEADERS.requests:
            if header == DEVICE_HEADERS.requests.x23_header:
                queue_id = data[6:10]
                logger.debug(
                    f"{lp} Device AUTH packet with starting queue ID: '{queue_id.hex(' ')}', replying..."
                )
                self.starting_queue_id = queue_id
                self.queue_ids.append(queue_id)
                await device.write(DEVICE_HEADERS.responses.auth_ack)
                # send a3, this is how the original cloud server does it.
                # ask for mesh info when device ack 0xa3 with 0xab.
                await asyncio.sleep(5)
                await self.send_a3(queue_id)
            # device wants to connect before accepting commands
            elif header == DEVICE_HEADERS.requests.xc3_header:
                logger.debug(f"{lp} CONNECTION REQUEST, replying...")
                await device.write(DEVICE_HEADERS.responses.connection_ack)
            # Ping/Pong
            elif header == DEVICE_HEADERS.requests.xd3_header:
                await device.write(DEVICE_HEADERS.responses.ping_ack)
                # logger.debug(f"{lp}xd3: Client sent HEARTBEAT, replying...")
            elif header == DEVICE_HEADERS.requests.xa3_header:
                logger.debug(f"{lp} APP ANNOUNCEMENT packet, replying...")
                ack = DEVICE_HEADERS.xab_generate_ack(queue_id, bytes(msg_id))
                # logger.debug(f"{lp} Sending ACK -> {ack.hex(' ')}")
                await device.write(ack)
            elif header == DEVICE_HEADERS.requests.xab_header:
                # We sent an 0xa3 packet, device is responding with 0xab. msg contains ascii 'xlink_dev'.
                # Request BT mesh info
                # logger.debug(
                #     f"{lp} DEVICE is ack'ing 0xa3, asking for BT mesh/Device Status info..."
                # )
                self.parse_mesh_status = True
                await self.ask_for_mesh_info()
            elif header == DEVICE_HEADERS.requests.x7b_header:
                # device is acking one of our x73 requests
                # can += 1 to the msg id
                # logger.debug(
                #     f"{lp} DEVICE is ack'ing 0x73 // queue: {queue_id.hex(' ')} // msg: {msg_id.hex(' ')}"
                # )
                pass

            # STATUS PACKET
            elif header == DEVICE_HEADERS.requests.x43_header:
                # Handle 0x43 device status packets from devices
                # 43 00 00 00 34 39 87 c8 57 01 01 06 [c7 90] 2a
                if packet_data:
                    if packet_data[:2] == bytes([0xC7, 0x90]):
                        # There is some sort of timestamp in the packet, not status
                        # look for ascii '*' (0x2A) and grab the data after it
                        ts_idx = packet_data.find(0x2A) + 1
                        ts = packet_data[ts_idx:]
                        logger.debug(
                            f"{lp} Device sent TIMESTAMP -> {ts.decode('ascii', errors='ignore')} - replying..."
                        )
                    else:
                        # 43 00 00 00 2d 39 87 c8 57 01 01 06| [(06 00 10) {03  C...-9..W.......
                        # 01 64 32 00 00 00 01} ff 07 00 00 00 00 00 00] 07  .d2.............
                        # 00 10 02 01 64 32 00 00 00 01 ff 07 00 00 00 00  ....d2..........
                        # 00 00
                        # status struct is 19 bytes long
                        struct_len = 19
                        logger.debug(
                            f"{lp} Device sent STATUS packet => '{packet_data.hex(' ')}', replying..."
                        )
                        try:
                            for i in range(0, packet_length, struct_len):
                                extracted = packet_data[i : i + struct_len]
                                status_struct = extracted[3:11]
                                await self.parse_status(status_struct)
                                # broadcast status data
                                await self.write(data, broadcast=True)
                        except IndexError:
                            pass
                        except Exception as e:
                            logger.error(f"{lp} EXCEPTION: {e}")
                # Its one of those queue id/msg id pings? 0x43 00 00 00 ww xx xx xx xx yy yy yy
                # Also notice these messages when another device gets a command
                else:
                    # logger.debug(f"{lp} received a 0x43 packet with no data, interpreting as PING, replying...")
                    pass
                ack = DEVICE_HEADERS.x48_generate_ack(bytes(msg_id))
                # logger.debug(f"{lp} Sending ACK -> {ack.hex(' ')}")
                await device.write(ack)

            # When the device sends a packet starting with 0x83, data is wrapped in 0x7e.
            # firmware version is sent without 0x7e boundaries
            elif header == DEVICE_HEADERS.requests.x83_header:
                if packet_data is not None:
                    logger.debug(f"{lp} DATA => {packet_data.hex(' ')}")
                    # 0x83 inner struct - not always bound by 0x7e (firmware response doesnt have it)
                    # firmware info, always seems to have 0x32 for header id byte
                    if packet_data[0] == 0x00:
                        # n_idx = packet_data.find(0x86)
                        n_idx = 20
                        # next 2 bytes tell us if it is network firmware or device firmware
                        # 0x01, 0x01 = device, 0x01, 0x00 = network
                        firmware_type = (
                            "device" if packet_data[n_idx + 2] == 0x01 else "network"
                        )
                        n_idx += 3
                        firmware_version = []
                        try:
                            for i in range(n_idx, len(packet_data[n_idx:])):
                                if packet_data[i] == 0x00:
                                    logger.debug(
                                        f"{lp} FIRMWARE VERSION for loop BREAKING at 0x00"
                                    )
                                    break
                                firmware_version.append(packet_data[i])
                        except IndexError:
                            pass
                        except Exception as e:
                            logger.error(
                                f"{lp} FIRMWARE VERSION for loop EXCEPTION: {e}"
                            )
                        logger.debug(
                            f"{lp} {firmware_type} FIRMWARE VERSION, HOW TO USE? -> {firmware_version}"
                        )

                    elif packet_data[0] == 0x7E:
                        # device self status
                        # 83 00 00 00 25 37 96 24 69 00 05 00 7e 21 00 00  ....%7.$i...~!..
                        #  00 fa db 13 00 34 22 11 05 00 [05] 00 db 11 02 01  .....4".........
                        #  [01 64 00 00 00 00] 00 00 b3 7e
                        ctrl_bytes = packet_data[5:7]
                        if ctrl_bytes == bytes([0xFA, 0xDB]):
                            id_idx = 14
                            ask_for_mesh_idx = 19
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
                            r = packet_data[r_idx]
                            g = packet_data[g_idx]
                            b = packet_data[b_idx]
                            # I think this is a device change struct. It receives a command and
                            # then broadcasts exactly what it changed. These packets ALWAYS have an 0x43 packet
                            # right after that has the correct status, so maybe we dont need to parse this status.
                            # Just log it
                            raw_status: bytes = bytes(
                                [dev_id, state, bri, tmp, r, g, b, 1]
                            )
                            logger.debug(
                                f"{lp} SELF STATUS => {bytes2list(raw_status)}"
                            )
                            # await self.parse_status(raw_status)
                else:
                    logger.warning(
                        f"{lp} packet with no data????? After stripping header, queue and "
                        f"msg id, there is no data to process?????"
                    )
                ack = DEVICE_HEADERS.x88_generate_ack(msg_id)
                logger.debug(f"{lp} Sending ACK -> {ack.hex(' ')}")
                await device.write(ack)

            elif header == DEVICE_HEADERS.requests.x73_header:
                if packet_data is not None:
                    # 0x73 should ALWAYS have 0x7e bound data.
                    ctrl_bytes = packet_data[5:7]
                    # check for boundary, all bytes between boundaries are for this request
                    if packet_data[0] == 0x7E:
                        inner_msg_id = packet_data[1]
                        # ctrl bytes 0xf9, 0x52 indicates this is a mesh info struct
                        if ctrl_bytes == bytes([0xF9, 0x52]):
                            # logger.debug(
                            #     f"{lp} innr msg id: {inner_msg_id} // MESH INFO? BASED "
                            #     f"ON -> ctrl_bytes = {ctrl_bytes.hex(' ')}"
                            # )
                            # find next 0x7e and extract the inner struct
                            end_bndry_idx = packet_data[1:].find(0x7E)
                            inner_struct = packet_data[1:end_bndry_idx]
                            # 15th byte of inner struct is start of mesh info
                            minfo_start_idx = 14
                            self.mesh_info = []
                            # from what i've seen, after the first 14 bytes, the mesh info is 24 bytes long and repeats
                            # until the end.
                            # Reset known device ids, mesh is the final authority on what devices are connected
                            self.known_device_ids = []
                            try:
                                loop_num = 0
                                for i in range(minfo_start_idx, len(inner_struct), 24):
                                    loop_num += 1

                                    mesh_dev_struct = inner_struct[i : i + 24]
                                    # logger.debug(f"{lp}x73: inner_struct[{i}:{i + 24}]={mesh_dev_struct}")
                                    dev_id = mesh_dev_struct[0]
                                    self.known_device_ids.append(dev_id)
                                    # first device id is the device id of the device we are connected to
                                    if loop_num == 1:
                                        self.id = dev_id
                                    # parse status from mesh info
                                    #  [05 00 44   01 00 00 44  01 00     00 00 00 64  00 00 00 00   00 00 00 00 00 00 00] - plug (devices are all connected to it via BT)
                                    #  [07 00 00   01 00 00 00  01 01     00 00 00 64  00 00 00 fe   00 00 00 f8 00 00 00] - direct connect full color A19 bulb
                                    #   ID  ? hub   ?  ?  ? hub  ? state   ?  ?  ? bri  ?  ?  ? tmp   ?  ?  ?  R  G  B  ?
                                    # 2 and 6 seem to be bt hub / bt master byte.
                                    hub_idx = 2
                                    state_idx = 8
                                    bri_idx = 12
                                    tmp_idx = 16
                                    r_idx = 20
                                    g_idx = 21
                                    b_idx = 22
                                    is_hub = mesh_dev_struct[hub_idx]
                                    dev_state = mesh_dev_struct[state_idx]
                                    dev_bri = mesh_dev_struct[bri_idx]
                                    dev_tmp = mesh_dev_struct[tmp_idx]
                                    dev_r = mesh_dev_struct[r_idx]
                                    dev_g = mesh_dev_struct[g_idx]
                                    dev_b = mesh_dev_struct[b_idx]
                                    # in mesh info, brightness can be > 0 when set to off
                                    if dev_state == 0 and dev_bri > 0:
                                        dev_bri = 0
                                    if is_hub > 0x00:
                                        # logger.debug(f"{lp} MESH INFO // Hub/Master BT device -> "
                                        #              f"{mesh_dev_struct.hex(' ')}")
                                        self.mesh_master = dev_id
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
                                        ]
                                    )
                                    self.mesh_info.append(bytes2list(raw_status))
                                    if self.parse_mesh_status is True:
                                        await self.parse_status(raw_status)

                            except IndexError:
                                # ran out of data
                                pass
                            except Exception as e:
                                logger.error(f"{lp} MESH INFO for loop EXCEPTION: {e}")
                            logger.debug(f"{lp} MESH INFO // {self.mesh_info}")
                            self.parse_mesh_status = False
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

                    ack = DEVICE_HEADERS.x7b_generate_ack(queue_id, msg_id)
                    # logger.debug(f"{lp} Sending ACK -> {ack.hex(' ')}")
                    await device.write(ack)
                else:
                    logger.warning(
                        f"{lp} packet with no data????? After stripping header, queue and "
                        f"msg id, there is no data to process?????"
                    )

        # unknown data we don't know the header for
        else:
            logger.debug(
                f"{lp} sent UNKNOWN HEADER! Don't know how to respond!\n"
                f"RAW: {data}\nINT: {bytes2list(data)}\nHEX: {data.hex(' ')}"
            )

    async def ask_for_mesh_info(self):
        """
        Ask the device for mesh info. As far as I can tell, this will return whatever
        devices are connected to the device you are querying. It may also trigger
        the device to send its own status packet.
        """

        # mesh_info = '73 00 00 00 18 2d e4 b5 d2 15 2c 00 7e 1f 00 00 00 f8 52 06 00 00 00 ff ff 00 00 56 7e'
        mesh_info_data = DEVICE_HEADERS.requests.x73_header
        # last byte is data len multiplier (multiply value by 256 if data len > 256)
        mesh_info_data += bytes([0x00, 0x00, 0x00])
        # data len
        mesh_info_data += bytes([0x18])
        # Queue ID
        mesh_info_data += self.starting_queue_id
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
        # logger.debug(
        #     f"Asking device ({self.address}) for BT mesh info: {mesh_info_data.hex(' ')}"
        # )
        await self.write(mesh_info_data)

    async def send_a3(self, q_id: bytes):
        a3_packet = bytes([0xA3, 0x00, 0x00, 0x00, 0x07])
        a3_packet += q_id
        # random 2 bytes
        rand_bytes = self.xa3_msg_id = random.getrandbits(16).to_bytes(2, "big")
        rand_bytes += bytes([0x00])
        self.xa3_msg_id += random.getrandbits(8).to_bytes(1, "big")
        a3_packet += rand_bytes
        logger.debug(f"Sending 0xa3 packet -> {a3_packet.hex(' ')}")
        await self.write(a3_packet)

    async def receive_task(self, client_addr: str):
        """
        Receive data from the device and respond to it. This is the main task for the device.
        It will respond to the device and handle the messages it sends.
        Runs in an infinite loop.
        """
        lp = f"{client_addr}:read:"
        while True:
            try:
                data: bytes = await self.read()
                if not data:
                    await asyncio.sleep(0.1)
                    continue
                await self.parse_raw_data(data)

            except Exception as e:
                logger.error(f"{lp} Exception in receive_task: {e}", exc_info=True)
                break

        logger.debug(f"{lp} receive_task FINISHED")

    async def read(self, chunk: Optional[int] = None):
        """Read data from the device if there is an open connection"""
        while self.reader is not None:
            if chunk is None:
                chunk = 1024
            async with self.read_lock:
                if self.reader:
                    if not self.reader.at_eof():
                        await asyncio.sleep(0)
                        return await self.reader.read(chunk)
                    else:
                        break
                else:
                    break

    async def write(self, data: bytes, broadcast: bool = False):
        """
        Write data to the device if there is an open connection

        :param data: The data to write to the device
        :param broadcast: If True, write to all devices connected to the server, not just this one
        """
        if not isinstance(data, bytes):
            raise ValueError(f"Data must be bytes, not {type(data)}")
        devs = []
        if broadcast is True:
            devs = g.server.http_devices.values()
        else:
            devs.append(self)

        for dev in devs:
            if dev.writer:
                if dev.writer.is_closing():
                    logger.warning(
                        f"{dev.address}: writer is closing, not writing data"
                    )
                else:
                    async with dev.write_lock:
                        dev.writer.write(data)
                        # logger.debug(f"{dev.address}: writing data -> {data}")
                        await asyncio.sleep(0)
                        await dev.writer.drain()

    async def close(self):
        logger.debug(f"{self.__class__.__name__} close() called")
        self.closing = True
        if self.writer:
            async with self.write_lock:
                self.writer.close()
                await self.writer.wait_closed()
                self.writer = None

        if self.reader:
            async with self.read_lock:
                self.reader.feed_eof()
                await asyncio.sleep(0.01)
                self.reader = None

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
    lp: str = "mqtt:"

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
            topic = "cync_lan"
            logger.warning("%s MQTT topic not set, using default: %s" % (lp, topic))

        if ha_topic is None:
            ha_topic = "homeassistant"
            logger.warning(
                "%s HomeAssistant topic not set, using default: %s" % (lp, ha_topic)
            )

        self.broker_address = broker_address
        self.client = amqtt_client.MQTTClient(
            config={"reconnect_retries": 0, "auto_reconnect": False}
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
        lp = f"{self.lp}start"
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
                except Exception:
                    pass
                logger.error("%s Will attempt reconnect within 60 seconds..." % lp)
                return
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
        logger.debug("AFTER HASS DISCOVERY, about to seed all devices as offline")

        # seed everything offline
        for device_id, device in g.server.devices.items():
            availability = b"offline"
            _ = await self.client.publish(
                f"{self.topic}/availability/{device_id}", availability, qos=QOS_0
            )

        self.tasks = [
            asyncio.create_task(self.pub_worker(self.pub_queue)),
            asyncio.create_task(self.sub_worker(self.sub_queue)),
            asyncio.create_task(self.start_subscribing()),
        ]

    async def start_subscribing(self):
        """Subscribe to topics and start an infinite loop to pull data from the MQTT broker."""
        lp = f"{self.lp}start_sub:"
        await self.client.subscribe(
            [
                (f"{self.topic}/set/#", QOS_1),
                (f"{self.topic}/devices", QOS_1),
                (f"{self.topic}/shutdown", QOS_1),
                (f"{self.ha_topic}/status", QOS_1),
            ]
        )
        logger.debug(f"{lp} Subscribed to topics, waiting for mqtt messages...")
        try:
            while True:
                message = await self.client.deliver_message()
                if message:
                    await asyncio.sleep(0)
                    await self.sub_queue.put(message)
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
                logger.debug(
                    f"{lp} Device ID: {device_id} status received from HTTP => {device_status}"
                )
                await self.parse_status(device_id, device_status)

            except Exception as e:
                logger.error("%s pub_worker exception: %s" % (lp, e), exc_info=True)
            finally:
                # Notify the queue that the "work item" has been processed.
                self.pub_queue.task_done()
                logger.debug(f"{lp} pub_queue.task_done() called")

    async def parse_status(self, device_id: int, device_status: DeviceStatus):
        lp = f"{self.lp}parse status:"
        if device_id not in g.server.devices:
            logger.error(
                f"{lp} Device ID {device_id} not found?! Have you deleted or added any devices recently? "
                f"You may need to re-export devices from your Cync account!"
            )
            return
        power_status = "OFF" if device_status.state == 0 else "ON"
        mqtt_dev_state = {"state": power_status}

        device: CyncDevice = g.server.devices[device_id]
        if device.is_plug:
            logger.debug(
                f"{lp} Converted HTTP status to MQTT switch => {self.topic}/status/{device_id}  {power_status}"
            )
            _ = await self.client.publish(
                f"{self.topic}/status/{device_id}",
                power_status.encode(),
                qos=QOS_0,
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

            # White tunable (if rgb bulb and no rgb data sent OR non rgb light)
            elif device.supports_temperature and device_status.temperature is not None:
                mqtt_dev_state["color_mode"] = "color_temp"
                mqtt_dev_state["color_temp"] = self.tlct_to_hassct(
                    device_status.temperature
                )

            logger.debug(
                f"{lp} Converting HTTP status to MQTT => {self.topic}/status/{device_id} "
                + json.dumps(mqtt_dev_state)
            )
            await asyncio.sleep(0)
            _ = await self.client.publish(
                f"{self.topic}/status/{device_id}",
                json.dumps(mqtt_dev_state).encode(),
                qos=QOS_0,
            )

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
                                    f"{lp} Device ID {device_id} not found, have you deleted or added any devices recently?"
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
                        elif (
                            topic[0] == self.ha_topic
                            and topic[1] == "status"
                            and payload.upper() == b"ONLINE"
                        ):
                            logger.debug(
                                f"{lp} HASS just rebooted or came back online, re-announce devices"
                            )
                            await self.homeassistant_discovery()
                            await asyncio.sleep(1)

                            for device_id, device in g.server.devices.items():
                                availability = b"online"
                                _ = await self.client.publish(
                                    f"{self.topic}/availability/{device_id}",
                                    availability,
                                    qos=QOS_0,
                                )
            except Exception as e:
                logger.error("%s sub_worker exception: %s" % (lp, e), exc_info=True)
            finally:
                # Notify the queue that the "work item" has been processed.
                sub_queue.task_done()
                logger.debug(f"{lp} sub_queue.task_done() called...")

    async def publish_devices(self):
        lp = f"{self.lp}publish_devices:"
        for device_id, device in g.server.devices.items():
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
                    f"{lp} {self.ha_topic}/devices/{device_id}  "
                    + json.dumps(device_config)
                )
                _ = await self.client.publish(
                    f"{self.ha_topic}/devices/{device_id}",
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
        logger.info(f"{lp} Starting HomeAssistant MQTT discovery...")
        for device_id, device in g.server.devices.items():
            if device.is_plug:
                switch_cfg = {
                    "name": device.name,
                    "command_topic": "{0}/set/{1}".format(self.topic, device_id),
                    "state_topic": "{0}/status/{1}".format(self.topic, device_id),
                    "avty_t": "{0}/availability/{1}".format(self.topic, device_id),
                    "pl_avail": "online",
                    "pl_not_avail": "offline",
                    "unique_id": device.mac.replace(":", ""),
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
                light_config = {
                    "name": device.name,
                    "command_topic": "{0}/set/{1}".format(self.topic, device_id),
                    "state_topic": "{0}/status/{1}".format(self.topic, device_id),
                    "avty_t": "{0}/availability/{1}".format(self.topic, device_id),
                    "pl_avail": "online",
                    "pl_not_avail": "offline",
                    "unique_id": device.mac.replace(":", ""),
                    "schema": "json",
                    "brightness": True,
                    "brightness_scale": 100,
                }
                if device.supports_temperature or device.supports_rgb:
                    light_config["color_mode"] = True
                    light_config["supported_color_modes"] = []
                    if device.supports_temperature:
                        light_config["supported_color_modes"].append("color_temp")
                        light_config["max_mireds"] = self.hass_maxct
                        light_config["min_mireds"] = self.hass_minct
                    if device.supports_rgb:
                        light_config["supported_color_modes"].append("rgb")

                try:
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
                        "homeassistant discovery - Unable to publish mqtt message... skipped -> %s"
                        % e
                    )
        logger.debug("HomeAssistant MQTT discovery complete")

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
    sub_run.add_argument(
        "config",
        type=Path,
        help="Path to the configuration file",
    )
    sub_run.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    sub_run.add_argument(
        "-e", "--env", help="Import environment variables from file", type=Path
    )

    sub_export = subparsers.add_parser(
        "export",
        help="Export Cync devices from the cloud service, Requires email and/or OTP from email",
    )
    sub_export.add_argument(
        "output_file",
        type=Path,
        help="Path to the output file",
    )
    sub_export.add_argument(
        "--email",
        "-e",
        help="Email address for Cync account, will send OTP to email provided",
        dest="email",
    )
    sub_export.add_argument(
        "--code" "--otp",
        "-o",
        "-c",
        help="One Time Password from email",
        dest="code",
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
        "--auth",
        help="Path to the auth token file",
        type=Path,
        dest="auth_file",
    )
    sub_certs = subparsers.add_parser(
        "certs",
        help="Generate self-signed certificates for the server",
    )
    sub_certs.add_argument(
        "common_name",
        help="Common Name for the server certificate",
        default="*.xlink.cn",
    )
    sub_certs.add_argument(
        "--output_dir",
        "-o",
        type=Path,
        help="Path to the output directory",
        default=Path("./certs"),
    )

    args = parser.parse_args()
    logger.debug(f"CLI args: {args}")
    return args


def generate_certs(
    key_out: Union[str, os.PathLike, None] = None,
    cert_out: Union[str, os.PathLike] = None,
    common_name: Optional[str] = None,
) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a self-signed certificate and private key using *.xlink.cn for Common Name (CN).
    You can write the key and/or cert by specifying the key_out and/or cert_out parameters.
    If no arguments are supplied, the key and cert are kept in memory, the user will need to write them to a file.


    :param key_out: The path to write the private key to. If None, the private key will not be written to a file.
    :param cert_out: The path to write the certificate to. If None, the certificate will not be written to a file.
    :param common_name: The Common Name (CN) for the certificate. If None, the CN will be set to "*.xlink.cn".
    :return: A tuple containing the private key and certificate data.
    """
    if not common_name:
        common_name = "*.xlink.cn"
    # Generate a new private key
    private_key: rsa.RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537, key_size=4096
    )

    # Create a certificate signing request (CSR)
    subject: x509.Name = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)]
    )
    csr: x509.CertificateSigningRequest = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )

    # Generate a self-signed certificate valid for 10 years
    issuer = subject
    cert: x509.Certificate = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .sign(private_key, hashes.SHA256())
    )
    if not key_out:
        key_out = Path().cwd() / "key.pem"
    if not cert_out:
        cert_out = Path().cwd() / "cert.pem"
    if any([key_out, cert_out]):
        cert_out = Path(cert_out)
        key_out = Path(key_out)
        chain_out = Path()

        if key_out is not None:
            # Write private key to file
            with key_out.open("wb") as key_file:
                key_file.write(
                    private_key.private_bytes(
                        Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
                    )
                )

        if cert_out is not None:
            # Write certificate to file
            with cert_out.open("wb") as cert_file:
                cert_file.write(cert.public_bytes(Encoding.PEM))
            chain_out = cert_out.parent / "server.pem"

        if key_out is not None and cert_out is not None:
            # Concatenate key.pem and cert.pem into server.pem
            with chain_out.open("wb") as server_pem:
                with key_out.open("rb") as key_pem:
                    server_pem.write(key_pem.read())
                with cert_out.open("rb") as cert_pem:
                    server_pem.write(cert_pem.read())

    return private_key, cert


if __name__ == "__main__":
    cli_args = parse_cli()
    if cli_args.command == "run":
        config_file = cli_args.config
        if not config_file.exists():
            raise FileNotFoundError(f"Config file not found: {config_file}")

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
            raise ke

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
        email = cli_args.email
        code = cli_args.code
        save_auth = cli_args.save_auth
        auth_output = cli_args.auth_file
        auth_file = cli_args.auth_file
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
            with cli_args.output_file.open("w") as f:
                f.write(yaml.dump(mesh_config))
        except Exception as e:
            logger.error(f"main: Export failed: {e}", exc_info=True)
        else:
            logger.info(f"main: Exported Cync devices to file: {cli_args.output_file}")

        if save_auth:
            if auth_output is None:
                logger.warning(
                    "main: No output file specified for saving Cync Cloud Auth, skipping saving auth data to file..."
                )
            else:
                logger.info(
                    "main: Attempting to save Cync Cloud Auth to file, PLEASE SECURE THIS FILE!"
                )
                try:
                    with open("./cync_auth.yaml", "w") as f:
                        f.write(yaml.dump({"token": access_token, "user": token_user}))
                except Exception as e:
                    logger.error(
                        "Failed to save auth token to file: %s" % e, exc_info=True
                    )
                else:
                    logger.info(
                        f"Saved auth token to file: {Path.cwd()}/cync_auth.yaml"
                    )
    elif cli_args.command == "certs":
        output_dir = cli_args.output_dir
        common_name = cli_args.common_name
        if not output_dir.exists():
            output_dir.mkdir()
        logger.info(
            f"Generating self-signed certificates for server using CN: {common_name}"
        )
        cert, key = generate_certs(common_name=common_name)
        cert_file = output_dir / "cync_cert.pem"
        key_file = output_dir / "cync_key.pem"
        cert_file.write_text(cert)
        key_file.write_text(key)
        logger.info(f"Certificates written to {cert_file} and {key_file}")


"""
# 2 devices joi the mesh. ID 2 and 3
03/16/24 21:45:48.0033 DEBUG - cync-lan cync-lan:533 -> 10.0.2.215:extract: Extracting packets from 43 bytes of raw data
83 00 00 00 26 39 87 c8 57 00 5e 00 7e 11 00 00 00 fa d0 14 00 fe 03 00 05 00 ff ff ea 11 02 05 a1 00 00 00 00 00 00 00 00 8b 7e

11 00 00 00 fa d0   14 00   fe  03 00 05 00  ff  ff   ea  11 02 05  a1 00 00 00 00 00 00 00 00  8b
17  0  0  0 [ctrl]  20  0  255   3  0  5  0 256 256  234  17 ID id 161  0  0  0  0  0  0  0  0 139
17  0  0  0 [ctrl]  20  0  25   28 51  0  0 256 256  234  17 ID id 161  1  3  1  0  0  0  0  0

03/16/24 21:45:54.0995 DEBUG - cync-lan cync-lan:533 -> 10.0.2.215:extract: Extracting packets from 43 bytes of raw data
83 00 00 00 26 39 87 c8 57 00 5f 00 7e 11 00 00 00 fa d0 14 00 19 22 33 07 00 ff ff ea 11 02 07 a1 01 03 01 00 00 00 00 00 01 7e

11 00 00 00 fa d0   14 00  19  22 33 07 00  ff  ff   ea  11 02 07  a1 01 03 01 00 00 00 00 00 01
17  0  0  0 [ctrl]  20  0  25  28 51  0  0 256 256  234  17 ID id 161  1  3  1  0  0  0  0  0

"""
