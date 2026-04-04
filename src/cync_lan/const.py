import logging
import os
import zoneinfo
from typing import Dict, List, Optional, Tuple, Union

import tzlocal

from cync_lan import __version__

__all__ = [
    "CYNC_EXPORT_HOST",
    "CYNC_OVERWRITE_CONFIG_FILE",
    "CYNC_EXPORT_HOST",
    "EXPORT_SRV_START_TASK_NAME",
    "MQTT_CLIENT_START_TASK_NAME",
    "nCYNC_START_TASK_NAME",
    "FOREIGN_LOG_FORMATTER",
    "LOG_FORMATTER",
    "TCP_BLACKHOLE_DELAY",
    "CYNC_MANUFACTURER",
    "CYNC_BRIDGE_OBJ_ID",
    "CYNC_MINK",
    "CYNC_MAXK",
    "ORIGIN_STRUCT",
    "CYNC_BRIDGE_DEVICE_REGISTRY_CONF",
    "CYNC_UUID_PATH",
    "LOCAL_TZ",
    "CYNC_CONFIG_DIR",
    "CYNC_ENABLE_EXPORTER",
    "CYNC_BASE_DIR",
    "CYNC_STATIC_DIR",
    "CYNC_EXPORT_PORT",
    "CYNC_UUID_PATH",
    "FACTORY_EFFECTS_BYTES",
    "LOCAL_TZ",
    "CYNC_CONFIG_FILE_PATH",
    "CYNC_CLOUD_AUTH_PATH",
    "CYNC_VERSION",
    "SRC_REPO_URL",
    "DEVICE_LWT_MSG",
    "CYNC_MQTT_CONN_DELAY",
    "CYNC_CMD_BROADCASTS",
    "CYNC_MAX_TCP_CONN",
    "CYNC_TCP_WHITELIST",
    "CYNC_API_BASE",
    "CYNC_MQTT_HOST",
    "CYNC_MQTT_PORT",
    "CYNC_MQTT_USER",
    "CYNC_MQTT_PASS",
    "CYNC_SSL_CERT",
    "CYNC_SSL_KEY",
    "CYNC_TOPIC",
    "CYNC_HASS_TOPIC",
    "CYNC_HASS_STATUS_TOPIC",
    "CYNC_HASS_BIRTH_MSG",
    "CYNC_HASS_WILL_MSG",
    "CYNC_SRV_PORT",
    "CYNC_SRV_HOST",
    "STREAM_CHUNK_SIZE",
    "YES_ANSWER",
    "CYNC_RAW",
    "CYNC_DEBUG",
    "CYNC_CORP_ID",
    "DATA_BOUNDARY",
    "RAW_MSG",
    "CYNC_LOG_NAME",
    "CYNC_ACCOUNT_USERNAME",
    "CYNC_ACCOUNT_PASSWORD",
    "CYNC_ACCOUNT_LANGUAGE",
]

YES_ANSWER = ("true", "1", "yes", "y", "t", 1, "on", "o")
LOCAL_TZ = zoneinfo.ZoneInfo(str(tzlocal.get_localzone()))
CYNC_LOG_NAME: str = "cync_lan"

LOG_FORMATTER = logging.Formatter(
    "%(asctime)s.%(msecs)d %(levelname)s [%(module)s:%(lineno)d] > %(message)s",
    "%m/%d/%y %H:%M:%S",
)
# adds logger name
FOREIGN_LOG_FORMATTER = logging.Formatter(
    "%(asctime)s.%(msecs)d %(levelname)s <%(name)s> [%(module)s:%(lineno)d] > %(message)s",
    "%m/%d/%y %H:%M:%S",
)
CYNC_VERSION: str = __version__
SRC_REPO_URL: str = "https://github.com/baudneo/cync-lan"
CYNC_API_BASE: str = "https://api.gelighting.com/v2/"
DEVICE_LWT_MSG: bytes = b"offline"

CYNC_SRV_HOST = os.environ.get("CYNC_SRV_HOST", "0.0.0.0")
CYNC_EXPORT_HOST = os.environ.get("CYNC_EXPORT_HOST", CYNC_SRV_HOST)
CYNC_EXPORT_SOURCE = os.environ.get("CYNC_EXPORT_SOURCE")

CYNC_HASS_APP = os.environ.get("CYNC_HASS_APP", "no") in YES_ANSWER

CYNC_ACCOUNT_LANGUAGE: str = os.environ.get("CYNC_ACCOUNT_LANGUAGE", "en-us").casefold()
CYNC_ACCOUNT_USERNAME: str = os.environ.get("CYNC_ACCOUNT_USERNAME", None)
CYNC_ACCOUNT_PASSWORD: str = os.environ.get("CYNC_ACCOUNT_PASSWORD", None)

CYNC_CMD_BROADCASTS: int = os.environ.get("CYNC_CMD_BROADCASTS", 2)
if not CYNC_CMD_BROADCASTS:
    CYNC_CMD_BROADCASTS = 2
else:
    try:
        CYNC_CMD_BROADCASTS = int(CYNC_CMD_BROADCASTS)
    except ValueError:
        CYNC_CMD_BROADCASTS = 2
CYNC_MAX_TCP_CONN: int = os.environ.get("CYNC_MAX_TCP_CONN", 8)
if not CYNC_MAX_TCP_CONN:
    CYNC_MAX_TCP_CONN = 8
else:
    try:
        CYNC_MAX_TCP_CONN = int(CYNC_MAX_TCP_CONN)
    except ValueError:
        CYNC_MAX_TCP_CONN = 8
CYNC_TCP_WHITELIST: Optional[Union[str, List[Optional[str]]]] = os.environ.get(
    "CYNC_TCP_WHITELIST"
)
CYNC_MQTT_HOST = os.environ.get("CYNC_MQTT_HOST", "homeassistant.local")
CYNC_MQTT_PORT = os.environ.get("CYNC_MQTT_PORT", 1883)
CYNC_MQTT_USER = os.environ.get("CYNC_MQTT_USER")
CYNC_MQTT_PASS = os.environ.get("CYNC_MQTT_PASS")
CYNC_TOPIC = os.environ.get("CYNC_TOPIC", "cync_lan")
CYNC_HASS_TOPIC = os.environ.get("CYNC_HASS_TOPIC", "homeassistant")
CYNC_HASS_STATUS_TOPIC = os.environ.get("CYNC_HASS_STATUS_TOPIC", "status")
CYNC_HASS_BIRTH_MSG = os.environ.get("CYNC_HASS_BIRTH_MSG", "online")
CYNC_HASS_WILL_MSG = os.environ.get("CYNC_HASS_WILL_MSG", "offline")
CYNC_MQTT_CONN_DELAY: int = int(os.environ.get("CYNC_MQTT_CONN_DELAY", 10))

CYNC_RAW = os.environ.get("CYNC_RAW_DEBUG", "0").casefold() in YES_ANSWER
CYNC_DEBUG = os.environ.get("CYNC_DEBUG", "0").casefold() in YES_ANSWER

CYNC_BASE_DIR: str = os.environ.get("CYNC_BASE_DIR", "/root/cync-lan")
CYNC_STATIC_DIR: str = os.environ.get("CYNC_STATIC_DIR", f"{CYNC_BASE_DIR}/www")
CYNC_CFGAPPEND_DIR: str = os.environ.get("CYNC_CFGAPPEND_DIR", "/config")
CYNC_OVERWRITE_CONFIG_FILE: bool = (
    os.environ.get("CYNC_OVERWRITE_CONFIG_FILE", "0").casefold() in YES_ANSWER
)
if CYNC_CFGAPPEND_DIR is not None and CYNC_CFGAPPEND_DIR:
    if not CYNC_CFGAPPEND_DIR.startswith("/"):
        CYNC_CFGAPPEND_DIR = f"/{CYNC_CFGAPPEND_DIR}"

CYNC_CONFIG_DIR = os.environ.get(
    "CYNC_CONFIG_DIR", f"{CYNC_BASE_DIR}{CYNC_CFGAPPEND_DIR}"
)

CYNC_CONFIG_FILE_PATH: str = f"{CYNC_CONFIG_DIR}/cync_mesh.yaml"
CYNC_UUID_PATH: str = f"{CYNC_CONFIG_DIR}/uuid.txt"
CYNC_CLOUD_AUTH_PATH: str = f"{CYNC_CONFIG_DIR}/.cloud_auth.yaml"

CYNC_SSL_CERT: str = os.environ.get(
    "CYNC_DEVICE_CERT", f"{CYNC_BASE_DIR}/certs/cert.pem"
)
CYNC_SSL_KEY: str = os.environ.get("CYNC_DEVICE_KEY", f"{CYNC_BASE_DIR}/certs/key.pem")

CYNC_BRIDGE_DEVICE_REGISTRY_CONF: dict = {}

CYNC_SRV_PORT = int(os.environ.get("CYNC_PORT", 23779))
CYNC_EXPORT_PORT = int(os.environ.get("CYNC_EXPORT_PORT", 23778))
STREAM_CHUNK_SIZE = 2048
CYNC_CORP_ID: str = "1007d2ad150c4000"
DATA_BOUNDARY = 0x7E
RAW_MSG = (
    " Set the CYNC_RAW_DEBUG env var to 1 to see the data" if CYNC_RAW is False else ""
)
CYNC_ENABLE_EXPORTER: bool = (
    os.environ.get("CYNC_ENABLE_EXPORTER", "1").casefold() in YES_ANSWER
)
# hardcoded: internally cync uses 0-100. So, no matter the bulbs actual kelvin range, it will work out.
CYNC_MINK: int = 2000
CYNC_MAXK: int = 7000
CYNC_BRIDGE_OBJ_ID: str = "cync_lan_bridge"
EXPORT_SRV_START_TASK_NAME = "ExportServer_START"
MQTT_CLIENT_START_TASK_NAME = "MQTTClient_START"
nCYNC_START_TASK_NAME = "CyncLanServer_START"
if CYNC_TCP_WHITELIST:
    CYNC_TCP_WHITELIST = CYNC_TCP_WHITELIST.split(",")
    CYNC_TCP_WHITELIST = [x.strip() for x in CYNC_TCP_WHITELIST if x]

FACTORY_EFFECTS_BYTES: Dict[str, Tuple[int, int]] = {
    "candle": (int(0x01), int(0xF1)),
    "cyber": (int(0x43), int(0x9F)),
    "rainbow": (int(0x02), int(0x7A)),
    "fireworks": (int(0x3A), int(0xDA)),
    "volcanic": (int(0x04), int(0xF4)),
    "aurora": (int(0x05), int(0x1C)),
    "happy_holidays": (int(0x06), int(0x54)),
    "red_white_blue": (int(0x07), int(0x4F)),
    "vegas": (int(0x08), int(0xE3)),
    "party_time": (int(0x09), int(0x06)),
}

ORIGIN_STRUCT = {
    "name": "cync-lan",
    "sw_version": CYNC_VERSION,
    "support_url": SRC_REPO_URL,
}

CYNC_MANUFACTURER = "Savant"
TCP_BLACKHOLE_DELAY: float = os.environ.get("CYNC_TCP_BLACKHOLE_DELAY", 14.75)
if TCP_BLACKHOLE_DELAY:
    if not isinstance(TCP_BLACKHOLE_DELAY, float):
        TCP_BLACKHOLE_DELAY = float(TCP_BLACKHOLE_DELAY)
