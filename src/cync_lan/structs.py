from __future__ import annotations

import asyncio
import datetime
import logging
import os
import time
from argparse import Namespace
from enum import StrEnum
from typing import TYPE_CHECKING, Coroutine, Dict, List, Optional, Tuple, Union

import uvloop
from pydantic import BaseModel, ConfigDict, computed_field
from pydantic.dataclasses import dataclass

from cync_lan.const import CYNC_LOG_NAME, YES_ANSWER

if TYPE_CHECKING:
    from cync_lan.cloud_api import CyncCloudAPI
    from cync_lan.exporter import ExportServer
    from cync_lan.main import CyncLAN
    from cync_lan.mqtt_client import MQTTClient
    from cync_lan.server import nCyncServer


logger = logging.getLogger(CYNC_LOG_NAME)


class GlobalObjEnv(BaseModel):
    """
    Environment variables for the global object.
    This is used to store environment variables that are used throughout the application.
    """

    account_username: Optional[str] = None
    account_password: Optional[str] = None
    mqtt_host: Optional[str] = None
    mqtt_port: Optional[int] = None
    mqtt_user: Optional[str] = None
    mqtt_pass: Optional[str] = None
    mqtt_topic: Optional[str] = None
    mqtt_hass_topic: Optional[str] = None
    mqtt_hass_status_topic: Optional[str] = None
    mqtt_hass_birth_msg: Optional[str] = None
    mqtt_hass_will_msg: Optional[str] = None
    cync_srv_host: Optional[str] = None
    cync_export_host: Optional[str] = None
    enable_export_server: Optional[bool] = None
    cync_srv_ssl_cert: Optional[str] = None
    cync_srv_ssl_key: Optional[str] = None
    appended_config_dir: Optional[str] = None
    base_dir: Optional[str] = None


class GlobalObject:
    cync_lan: Optional["CyncLAN"] = None
    ncync_server: Optional["nCyncServer"] = None
    mqtt_client: Optional["MQTTClient"] = None
    loop: Union[uvloop.Loop, asyncio.AbstractEventLoop, None] = None
    export_server: Optional["ExportServer"] = None
    cloud_api: Optional["CyncCloudAPI"] = None
    tasks: List[asyncio.Task] = []
    env: GlobalObjEnv = GlobalObjEnv()
    uuid: Optional[uuid.UUID] = None
    cli_args: Optional[Namespace] = None
    _last_valid_state_ts: float = 0.0

    _instance: Optional["GlobalObject"] = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @property
    def last_valid_state_ts(self):
        return self._last_valid_state_ts

    @last_valid_state_ts.setter
    def last_valid_state_ts(self, value):
        self._last_valid_state_ts = value
        # TODO: send MQTT data, this can be used to trigger a restart
        # if self.mqtt_client:
        #     asyncio.create_task(self.mqtt_client.publish, "")


    def reload_env(self):
        """Re-evaluate environment variables to update constants."""
        global CYNC_MQTT_HOST, CYNC_MQTT_PORT, CYNC_MQTT_USER, CYNC_MQTT_PASS
        global CYNC_TOPIC, CYNC_HASS_TOPIC, CYNC_HASS_STATUS_TOPIC, CYNC_BASE_DIR
        global \
            CYNC_HASS_BIRTH_MSG, \
            CYNC_HASS_WILL_MSG, \
            CYNC_SRV_HOST, \
            CYNC_EXPORT_HOST, \
            CYNC_ENABLE_EXPORTER
        global \
            CYNC_SSL_CERT, \
            CYNC_SSL_KEY, \
            CYNC_ACCOUNT_USERNAME, \
            CYNC_ACCOUNT_PASSWORD, \
            PERSISTENT_DIR
        self.env.base_dir = CYNC_BASE_DIR = os.environ.get(
            "CYNC_BASE_DIR", "/root/cync-lan"
        )
        self.env.account_username = CYNC_ACCOUNT_USERNAME = os.environ.get(
            "CYNC_ACCOUNT_USERNAME", None
        )
        self.env.account_password = CYNC_ACCOUNT_PASSWORD = os.environ.get(
            "CYNC_ACCOUNT_PASSWORD", None
        )
        self.env.mqtt_host = CYNC_MQTT_HOST = os.environ.get(
            "CYNC_MQTT_HOST", "homeassistant.local"
        )
        self.env.mqtt_port = CYNC_MQTT_PORT = int(
            os.environ.get("CYNC_MQTT_PORT", 1883)
        )
        self.env.mqtt_user = CYNC_MQTT_USER = os.environ.get("CYNC_MQTT_USER")
        self.env.mqtt_pass = CYNC_MQTT_PASS = os.environ.get("CYNC_MQTT_PASS")
        self.env.mqtt_topic = CYNC_TOPIC = os.environ.get("CYNC_TOPIC", "cync_lan")
        self.env.mqtt_hass_topic = CYNC_HASS_TOPIC = os.environ.get(
            "CYNC_HASS_TOPIC", "homeassistant"
        )
        self.env.mqtt_hass_status_topic = CYNC_HASS_STATUS_TOPIC = os.environ.get(
            "CYNC_HASS_STATUS_TOPIC", "status"
        )
        self.env.mqtt_hass_birth_msg = CYNC_HASS_BIRTH_MSG = os.environ.get(
            "CYNC_HASS_BIRTH_MSG", "online"
        )
        self.env.mqtt_hass_will_msg = CYNC_HASS_WILL_MSG = os.environ.get(
            "CYNC_HASS_WILL_MSG", "offline"
        )
        self.env.cync_srv_host = CYNC_SRV_HOST = os.environ.get(
            "CYNC_SRV_HOST", "0.0.0.0"
        )
        self.env.cync_export_host = CYNC_EXPORT_HOST = os.environ.get(
            "CYNC_EXPORT_HOST", CYNC_SRV_HOST
        )
        self.env.enable_export_server = CYNC_ENABLE_EXPORTER = (
            os.environ.get("CYNC_ENABLE_EXPORT", "0").casefold() in YES_ANSWER
        )
        self.env.cync_srv_ssl_cert = CYNC_SSL_CERT = os.environ.get(
            "CYNC_DEVICE_CERT", f"{CYNC_BASE_DIR}/certs/cert.pem"
        )
        self.env.cync_srv_ssl_key = CYNC_SSL_KEY = os.environ.get(
            "CYNC_DEVICE_KEY", f"{CYNC_BASE_DIR}/certs/key.pem"
        )
        self.env.appended_config_dir = PERSISTENT_DIR = os.environ.get(
            "CYNC_CONFIG_DIR", "/config"
        )



@dataclass(config=ConfigDict(arbitrary_types_allowed=True))
class Tasks:
    receive: Optional[asyncio.Task] = None
    send: Optional[asyncio.Task] = None
    callback_cleanup: Optional[asyncio.Task] = None

    def __iter__(self):
        tasks = [self.receive, self.send, self.callback_cleanup]
        for task in tasks:
            if task is not None:
                yield task

    def __len__(self):
        tasks = [self.receive, self.send, self.callback_cleanup]
        # remove any that are None
        tasks = [task for task in tasks if task is not None]
        return len(list(tasks))


    async def cancel_all(self):
        """Cancels all active tasks and waits for them to finish."""
        active_tasks = list(self)
        if not active_tasks:
            return
        for task in active_tasks:
            task.cancel()
        await asyncio.gather(*active_tasks, return_exceptions=True)
        # clear them, not getting bit again.
        self.receive = None
        self.send = None
        self.callback_cleanup = None


class ControlMessageCallback:
    id: int
    message: Union[None, str, bytes, List[int]] = None
    sent_at: Optional[float] = None
    callback: Optional[Union[asyncio.Task, Coroutine]] = None

    def __init__(
        self,
        msg_id: int,
        message: Union[None, str, bytes, List[int]],
        sent_at: float,
        callback: Union[asyncio.Task, Coroutine],
    ):
        self.id = msg_id
        self.message = message
        self.sent_at = sent_at
        self.callback = callback
        self.lp = f"CtrlMessageCallback:{self.id}:"

    @property
    def elapsed(self) -> float:
        return time.time() - self.sent_at

    def __str__(self):
        return f"CtrlMessageCallback ID: {self.id} elapsed: {self.elapsed:.5f}s"

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other: int):
        return self.id == other

    def __hash__(self):
        return hash(self.id)

    def __call__(self):
        if self.callback:
            return self.callback
        else:
            logger.debug(f"{self.lp} No callback set, skipping...")
            return None


class Messages:
    control: Dict[int, ControlMessageCallback]

    def __init__(self):
        self.control = dict()


@dataclass
class CacheData:
    """Cache to store data between binary packets"""
    all_data: bytes = b""
    timestamp: float = 0
    data: bytes = b""
    data_len: int = 0
    needed_len: int = 0


class DeviceStatus(BaseModel):
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


@dataclass
class MeshInfo:
    status: List[Optional[List[Optional[int]]]]
    id_from: int


class PhoneAppStructs:
    def __iter__(self):
        return iter([self.requests, self.responses])

    @dataclass
    class AppRequests:
        auth_header: Tuple[int] = (0x13, 0x00, 0x00, 0x00)
        connect_header: Tuple[int] = (0xA3, 0x00, 0x00, 0x00)
        headers: Tuple[int] = (0x13, 0xA3)

        def __iter__(self):
            return iter(self.headers)

    @dataclass
    class AppResponses:
        auth_resp: Tuple[int] = (0x18, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00)
        headers: Tuple[int] = 0x18

        def __iter__(self):
            return iter(self.headers)

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
        # TODO: figure out correct bytes for this
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
    def xab_generate_ack(queue_id: bytes, msg_id: bytes) -> bytes:
        """
        Respond to a 0xAB packet from the device.
        Requires queue_id and msg_id to reply with.
        Has ascii 'xlink_dev' in reply.
        """
        # 'xlink_dev' (9 bytes) + 948 null bytes + tail (4 bytes) = 961 bytes
        payload = b'xlink_dev' + bytes(948) + b'\xe3\x4f\x02\x10'
        total_len = len(queue_id) + len(msg_id) + len(payload)
        # divmod(x, 256) gives us (x // 256, x % 256)
        # length_factor increments every 256 bytes, length_byte rolls over to 0
        length_factor, length_byte = divmod(total_len, 256)
        # Construct the header: 0xAB, 0x00, 0x00, <factor>, <length>
        header = b'\xab\x00\x00' + bytes([length_factor, length_byte])

        return header + queue_id + msg_id + payload

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


APP_HEADERS = PhoneAppStructs()
DEVICE_STRUCTS = DeviceStructs()
ALL_HEADERS = list(DEVICE_STRUCTS.headers) + list(APP_HEADERS.headers)


class RawTokenData(BaseModel):
    """
    Model for cloud token data.
    """

    access_token: str
    user_id: Union[str, int]
    expire_in: Union[str, int]
    refresh_token: str
    authorize: str


class ComputedTokenData(RawTokenData):
    issued_at: datetime.datetime

    @computed_field
    @property
    def expires_at(self) -> Optional[datetime.datetime]:
        """
        Calculate the expiration time of the token based on the issued time and expires_in.
        Returns:
            datetime.datetime: The expiration time in UTC.
        """
        if self.issued_at and self.expire_in:
            return self.issued_at + datetime.timedelta(seconds=self.expire_in)
        return None

    # expires_at: Optional[datetime] = None

    # def model_post_init(self, __context) -> None:
    #     if self.expires_in:
    #         self.expires_at = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=self.expires_in)


class FanSpeed(StrEnum):
    OFF = "off"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    MAX = "max"


class EndpointState(BaseModel):
    """
    Holds the individual state for a specific endpoint (outlet, bulb, etc.).
    Endpoint is the logical device. Node is the physical device (TCP/BTLE conn).

    Args:
        name (str): The name of the endpoint.
        node_id (int): The node ID of the endpoint.
        id (int, optional): The sub ID of the endpoint. Defaults to 0.
        power (int, optional): The power state of the endpoint. Defaults to 0.
        brightness (int, optional): The brightness state of the endpoint. Defaults to 0.
        temperature (int, optional): the temperature state of the endpoint. Defaults to 0.
        red (int, optional): the red state of the endpoint. Defaults to 0.
        green (int, optional): the green state of the endpoint. Defaults to 0.
        blue (int, optional): the blue state of the endpoint. Defaults to 0.
    """

    name: str
    node_id: int
    id: int = 0
    power: int = 0
    brightness: int = 0
    temperature: int = 0
    red: int = 0
    green: int = 0
    blue: int = 0

    def __str__(self):
        return (
            f"{self.name} ({self.node_id}/{self.id}): pow={self.power} bri={self.brightness} temp={self.temperature} || "
            f"r={self.red} g={self.green} b={self.blue}"
        )

    def __repr__(self):
        return self.__str__()
