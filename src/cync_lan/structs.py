from __future__ import annotations

import asyncio
import datetime
import logging
import os
import time
from argparse import Namespace
from enum import StrEnum
from typing import TYPE_CHECKING, Coroutine, Dict, List, Optional, Tuple, Union
import uuid

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
    app_mitm_logging: bool = False


class GlobalObject:
    cync_lan: Optional["CyncLAN"] = None
    ncync_server: Optional["nCyncServer"] = None
    mqtt_client: Optional["MQTTClient"] = None
    loop: Union[uvloop.Loop, asyncio.AbstractEventLoop, None] = None
    export_server: Optional["ExportServer"] = None
    cloud_api: Optional["CyncCloudAPI"] = None
    tasks: List[Optional[asyncio.Task]]
    env: GlobalObjEnv = GlobalObjEnv()
    uuid: Optional[uuid.UUID] = None
    _last_valid_state_ts: float = 0.0

    _instance: Optional["GlobalObject"] = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.tasks = []
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
        self.env.app_mitm_logging = (
            os.environ.get("CYNC_APP_MITM_LOGGING", "0").casefold() in YES_ANSWER
        )


@dataclass(config=ConfigDict(arbitrary_types_allowed=True))
class Tasks:
    receive: Optional[asyncio.Task] = None
    send: Optional[asyncio.Task] = None
    callback_cleanup: Optional[asyncio.Task] = None
    proxy_task: Optional[asyncio.Task] = None

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


class MessageCache:
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


class RawTokenStruct(BaseModel):
    """
    Model for cloud token data.
    """

    access_token: str
    user_id: Union[str, int]
    expire_in: Union[str, int]
    refresh_token: str
    authorize: str


class ComputedTokenStruct(RawTokenStruct):
    issued_at: datetime.datetime

    @computed_field
    @property
    def expires_at(self) -> Optional[datetime.datetime]:
        """
        Calculate the expiration time of the token based on the issued_at time and expires_in.
        Returns:
            datetime.datetime: The expiration time in UTC.
        """
        if self.issued_at and self.expire_in:
            return self.issued_at + datetime.timedelta(seconds=self.expire_in)
        return None


class FanSpeed(StrEnum):
    OFF = "off"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    MAX = "max"


class EntityState(BaseModel):
    """
    Holds the individual state for a specific entity (outlet, bulb, etc.).
    entity is the logical device. Node is the physical device (TCP/BTLE conn).

    Args:
        name (str): The name of the entity.
        dev_id (int): The node ID of the entity.
        sub_id (int, optional): The sub ID of the entity. Defaults to 0.
        power (int, optional): The power state of the entity. Defaults to 0.
        brightness (int, optional): The brightness state of the entity. Defaults to 0.
        temperature (int, optional): the temperature state of the entity. Defaults to 0.
        red (int, optional): the red state of the entity. Defaults to 0.
        green (int, optional): the green state of the entity. Defaults to 0.
        blue (int, optional): the blue state of the entity. Defaults to 0.
        recently_seen (int, optional): has reported its state to BTLE mesh lately. Defaults to 1.
    """

    name: str = None
    dev_id: int
    # sub_id of the node_id
    sub_id: int = 0
    power: int = 0
    brightness: int = 0
    temperature: int = 0
    red: int = 0
    green: int = 0
    blue: int = 0
    recently_seen: int = 1

    def __str__(self):
        return (
            f"{self.name} ({self.dev_id}{'/{}'.format(self.sub_id) if self.sub_id > 0 else ''}): pow={self.power} bri={self.brightness} temp={self.temperature} ["
            f"r={self.red} g={self.green} b={self.blue}] stale: {self.recently_seen == 0}"
        )

    def __repr__(self):
        return self.__str__()
