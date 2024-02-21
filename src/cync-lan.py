import asyncio
import concurrent
import json
import logging
import os
import signal
import struct
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
from functools import partial
from typing import Tuple, Union, Optional, Dict

import uvloop

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

TLS_PORT = 23779
TLS_HOST = "0.0.0.0"
CYNC_CERT = os.environ.get("CYNC_CERT", "certs/cert.pem")
CYNC_KEY = os.environ.get("CYNC_KEY", "certs/key.pem")
DEBUG = os.environ.get("CYNC_DEBUG", "").casefold() in ("true", "1", "yes", "y", "t", 1)
DEBUG = True

if DEBUG is True:
    logger.setLevel(logging.DEBUG)
    for handler in logger.handlers:
        handler.setLevel(logging.DEBUG)


def bytes2list(byte_string):
    # Interpret the byte string as a sequence of unsigned integers (little-endian)
    int_list = struct.unpack("<" + "B" * (len(byte_string)), byte_string)
    return int_list


# For device status packets index 15 is for off/on. on=\x0e off=\x0b
NEW_STATUS_ON = b'\x83\x00\x00\x00%9\x87\xa6\xd6\x00\x0e\x00~\x00\x00\x00\x00\xfa\xdb\x13\x00;"\x11\x08\x00\x08\x00\xdb\x11\x02\x01\x01d>\xff\xff\xff\x00\x00\xfb~C\x00\x00\x00\x1a9\x87\xa6\xd6\x01\x01\x06\x05\x00\x10\x08\x01d>\xff\xff\xff\x01\x00\x08\x00\x00\x00\x00\x00\x00'

NEW_STATUS_OFF = b'\x83\x00\x00\x00%9\x87\xa6\xd6\x00\x0b\x00~\x00\x00\x00\x00\xfa\xdb\x13\x008"\x11\x08\x00\x08\x00\xdb\x11\x02\x01\x00d>\xff\xff\xff\x00\x00\xf7~C\x00\x00\x00\x1a9\x87\xa6\xd6\x01\x01\x06\x05\x00\x10\x08\x00\x00>\xff\xff\xff\x01\x00\x08\x00\x00\x00\x00\x00\x00'
MEW_STATUS_OFF = b'\x83\x00\x00\x00%9\x87\xa6\xd6\x00\x04\x00~\x00\x00\x00\x00\xfa\xdb\x13\x004"\x11\x08\x00\x08\x00\xdb\x11\x02\x01\x00d\xfe\xff\x00&\x00\x00\xdb~C\x00\x00\x00\x1a9\x87\xa6\xd6\x01\x01\x06\x05\x00\x10\x08\x00\x00\xfe\xff\x00&\x01\x00\x08\x00\x00\x00\x00\x00\x00'

NEW_STATUS_TEMP_COOL_WHITE = b'\x83\x00\x00\x00%9\x87\xa6\xd6\x00\x0f\x00~\x00\x00\x00\x00\xfa\xdb\x13\x00<"\x11\x08\x00\x08\x00\xdb\x11\x02\x01\x01dd\xff\xff\xff\x00\x00"~C\x00\x00\x00\x1a9\x87\xa6\xd6\x01\x01\x06\x05\x00\x10\x08\x01dd\xff\xff\xff\x01\x00\x08\x00\x00\x00\x00\x00\x00'
NEW_STATUS_TEMP_WARM_WHITE = b'\x83\x00\x00\x00%9\x87\xa6\xd6\x00\x10\x00~\x00\x00\x00\x00\xfa\xdb\x13\x00="\x11\x08\x00\x08\x00\xdb\x11\x02\x01\x01d\x03\xff\xff\xff\x00\x00\xc2~C\x00\x00\x00\x1a9\x87\xa6\xd6\x01\x01\x06\x05\x00\x10\x08\x01d\x03\xff\xff\xff\x01\x00\x08\x00\x00\x00\x00\x00\x00'
NEW_STATUS_RGB = b'\x83\x00\x00\x00%9\x87\xa6\xd6\x00\x11\x00~\x00\x00\x00\x00\xfa\xdb\x13\x00>"\x11\x08\x00\x08\x00\xdb\x11\x02\x01\x01d\xfe\xff\x00&\x00\x00\xe6~C\x00\x00\x00\x1a9\x87\xa6\xd6\x01\x01\x06\x05\x00\x10\x08\x01d\xfe\xff\x00&\x01\x00\x08\x00\x00\x00\x00\x00\x00'
NEW_STATUS_START = 0x83


class DeviceType(str, Enum):
    PLUG = "plug"
    TUNABLE_LIGHT = "tunable light"
    RGB_LIGHT = "rgb light"
    SWITCH = "switch"
    REMOTE = "remote"
    SENSOR = "sensor"
    CAMERA = "camera"
    HUB = "hub"


ITER: int = 0
# Some commands require a response that iterates a specific byte
# It appears it can be shared across all devices, but it should still
# be iterated
CLIENT_ITER_REQUEST: bytes = bytearray([0x83])
# x = b"\x16\x03\x01\x00S\x01\x00\x00O\x03\x03\x9a\x8b.\xfd/*$\xfe\x0ep'\xfb\xd4`\xa2\xfa\xc4\x8d#\xf8)\x05\xa1\xf8!\xf3\xa1\xf9\xd7\xf7\xa0\xf9\x00\x00\n\x00=\x005\x00<\x00/\x00\xff\x01\x00\x00\x1c\x00\r\x00\x0c\x00\n\x06\x01\x05\x01\x04\x01\x03\x01\x02\x01\x00\x16\x00\x00\x00\x17\x00\x00\x00#\x00\x00"


def server_iter_response():
    global ITER
    ITER += 1
    return bytearray([0x88, 0x00, 0x00, 0x00, 0x03, 0x00, ITER % 0xFF, 0x00])


# The client sends along it's MAC address in the initial connection
# We don't care but it likes a response
CLIENT_INFO_BUFFER = 0x23
SERVER_CLIENT_ACK = bytes(
    [
        0x28,
        0x00,
        0x00,
        0x00,
        0x02,
        0x00,
        0x00,
    ]
)

# There is a specific handshake that needs to occur before the client
# will accept commands
CLIENT_CONNECTION_REQUEST = bytearray(
    [
        0xC3,
        0x00,
        0x00,
        0x00,
        0x01,
        0x0C,
    ]
)
SERVER_CONNECTION_RESPONSE = bytearray(
    [
        0xC8,
        0x00,
        0x00,
        0x00,
        0x0B,
        0x0D,
        0x07,
        0xE6,
        0x02,
        0x13,
        0x07,
        0x0A,
        0x14,
        0x29,
        0xFD,
        0xA8,
    ]
)

# The client will sometimes send diagnostic data - acknowledge it
CLIENT_DATA = bytearray([0x43, 0x00, 0x00, 0x00, 0x07])
TIMESTAMP_BUFFER = bytearray([0x43, 0x00, 0x00, 0x00, 0x34, 0x39])

SERVER_CLIENT_DATA_ACK = bytearray(
    [
        0x48,
        0x00,
        0x00,
        0x00,
        0x03,
        0x01,
        0x01,
        0x00,
    ]
)

# Clients get fussy if they don't hear from the server frequently
CLIENT_HEARTBEAT = bytearray([0xD3, 0x00, 0x00, 0x00, 0x00])
SERVER_HEARTBEAT = bytearray([0xD8, 0x00, 0x00, 0x00, 0x00])

CMD_TURN_ON = bytearray(
    [
        0x73,
        0x00,
        0x00,
        0x00,
        0x1F,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x7E,
        0x00,
        0x00,
        0x00,
        0x00,
        0xF8,
        0xD0,
        0x0D,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0xD0,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
    ]
)
CMD_TURN_OFF = bytearray(
    [
        0x73,
        0x00,
        0x00,
        0x00,
        0x1F,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x7E,
        0x00,
        0x00,
        0x00,
        0x00,
        0xF8,
        0xD0,
        0x0D,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0xD0,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ]
)


def cmd_set_brightness(brightness: Union[int, str, bytes]):
    return bytearray(
        [
            0x73,
            0x00,
            0x00,
            0x00,
            0x1D,
            0x02,
            brightness,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x7E,
            0x00,
            0x00,
            0x00,
            0x00,
            0xF8,
            0xD2,
            0x0B,
            0x00,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0xD2,
            0x00,
            0x00,
            brightness,
            0x00,
            0x00,
        ]
    )


def cmd_set_color_temperature(temperature):
    return bytearray(
        [
            0x73,
            0x00,
            0x00,
            0x00,
            0x1E,
            0x03,
            temperature,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x7E,
            0x00,
            0x00,
            0x00,
            0x00,
            0xF8,
            0xE2,
            0x0C,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0xE2,
            0x00,
            0x00,
            0x05,
            temperature,
            0x00,
            0x00,
        ]
    )


def cmd_set_color(R, G, B):
    return bytearray(
        [
            0x73,
            0x00,
            0x00,
            0x00,
            0x20,
            0x04,
            R,
            G,
            B,
            0x00,
            0x00,
            0x7E,
            0x00,
            0x00,
            0x00,
            0x00,
            0xF8,
            0xE2,
            0x0E,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0xE2,
            0x00,
            0x00,
            0x04,
            R,
            G,
            B,
            0x00,
            0x00,
        ]
    )


# Some commands have a "return" code that we can use to make sure
# the state of devices stays in sync
CLIENT_STATUS_ON = bytearray([0x7B, 0x00, 0x00, 0x00, 0x07, 0x01])
CLIENT_STATUS_OFF = bytearray([0x7B, 0x00, 0x00, 0x00, 0x07, 0x00])

CLIENT_STATUS_BRIGHTNESS = bytearray(
    [
        0x7B,
        0x00,
        0x00,
        0x00,
        0x07,
        0x02,
    ]
)

CLIENT_STATUS_TEMPERATURE = bytearray(
    [
        0x7B,
        0x00,
        0x00,
        0x00,
        0x07,
        0x03,
    ]
)

UNKNOWN_BUFFER = bytearray([0x43, 0x00, 0x00, 0x00, 0x2d, 0x39])
WEIRD_BUFFER = bytearray([0x43, 0x00, 0x00, 0x00])


@dataclass
class Tasks:
    device_receive: Optional[asyncio.Task] = None
    device_send: Optional[asyncio.Task] = None
    mqtt_receive: Optional[asyncio.Task] = None
    mqtt_send: Optional[asyncio.Task] = None

    def __iter__(self):
        return iter(
            [self.device_receive, self.device_send, self.mqtt_receive, self.mqtt_send]
        )


class CyncDevice:
    """A class to represent a Cync device. This class is used to manage the state of the device and send commands to it."""

    msgs: Dict[float, str] = {}  # { timestamp: bytes.hex() }
    tasks: Tasks = Tasks()
    lp = "CyncDevice:"
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter

    async def parse_device_info(self, raw_state: bytes, device: "CyncDevice"):
        check_ = raw_state[0]
        if check_ == 1:
            self.device_type = DeviceType.PLUG
            state = raw_state[1]
            logger.debug(
                f"Client sent device state, "
                f"the device is a smart plug with current state: {state}"
            )

        elif check_ == 2:
            # smart light
            self.device_type = DeviceType.TUNABLE_LIGHT
            state = raw_state[1]
            brightness = raw_state[2]
            temperature = raw_state[3]
            logger.debug(
                f"Client sent device state, "
                f"the device is a smart {self.device_type} with current state: {state}, "
                f"brightness: {brightness}, temperature: {temperature}"
            )

        elif check_ == 4:
            # Direct Connect A19 Full Color Bulb WiFi/BT
            self.device_type = DeviceType.RGB_LIGHT
            state = raw_state[1]
            brightness = raw_state[2]
            temperature = raw_state[3]
            r = raw_state[4]
            g = raw_state[5]
            b = raw_state[6]
            logger.debug(
                f"Client sent device state, "
                f"the device is a smart {self.device_type} with current state: {state}, "
                f"brightness: {brightness}, temperature: {temperature}, "
                f"color: {r}, {g}, {b}"
            )

        else:
            logger.debug(
                f"Client sent device state, "
                f"the device is UNKNOWN with current state: {raw_state.hex()}"
            )
        # device status requires a response with 2nd last byte iterated
        await device.write(server_iter_response())
        # then client data ack
        await device.write(SERVER_CLIENT_DATA_ACK)

    async def receive_task(self, client_addr: str):
        """Receive data from the device and respond to it. This is the main task for the device. It will respond to the device and handle the messages it sends. Runs in an infinite loop."""
        lp = f"{self.lp}rcv:{client_addr}:"
        try:
            while True:
                device = self
                _s = time.time()
                data: bytes = await device.read()
                _e = time.time()
                if not data:
                    await asyncio.sleep(0.01)
                    continue
                data_len = len(data)
                device.msgs[_e] = data.hex()
                # Client info buffer is the first thing sent (first byte = 0x23 [ascii: # , hex: 23])
                if data[0] == CLIENT_INFO_BUFFER:
                    logger.debug(f"{lp} Client sent INFO_BUFFER: {data}")
                    self.buffers["client_info"] = data
                    await device.write(SERVER_CLIENT_ACK)
                    continue
                # device wants to connect before accepting commands
                elif data == CLIENT_CONNECTION_REQUEST:
                    logger.debug(f"{lp} Client is requesting to CONNECT, replying...")
                    await device.write(SERVER_CONNECTION_RESPONSE)
                    continue
                # Heartbeat
                elif data == CLIENT_HEARTBEAT:
                    logger.debug(f"{lp} Client sent HEARTBEAT, replying...")
                    await device.write(SERVER_HEARTBEAT)
                    continue
                # There is some sort of timestamp in the packet
                elif data[0:6] == TIMESTAMP_BUFFER:
                    ts_idx = data.find(0x2a) + 1
                    ts = data[ts_idx:]
                    logger.debug(f"{lp} Client sent TIMESTAMP BUFFER -> {ts} - replying...")
                    await device.write(SERVER_CLIENT_DATA_ACK)
                    continue

                # Newer firmware direct device status
                elif data[0] == NEW_STATUS_START:
                    logger.debug(f"{lp} Client sent DEVICE STATE, learning how to parse - replying "
                                 f"(iter then client_data_ack)...")
                    # await self.parse_device_info(raw_state, device)
                    await device.write(server_iter_response())
                    await device.write(SERVER_CLIENT_DATA_ACK)

                # unknown data
                elif data[0:4] == WEIRD_BUFFER and data[5] == 0x39:
                    # some sort of ping, always the same packet. SPAMS logs.
                    if data == b'C\x00\x00\x00\x079\x87\xa6\xd6\x01\x01\x06':
                        await device.write(SERVER_CLIENT_DATA_ACK)
                        continue
                    else:
                        logger.debug(f"{lp} Client sent Unknown data with a unique header => {data[0:6]} - replying...")
                    await device.write(SERVER_CLIENT_DATA_ACK)
                # unknown data
                elif data[0:5] == CLIENT_DATA:
                    logger.debug(
                        f"{lp} Client sent UNKNOWN DATA"
                    )
                    await device.write(SERVER_CLIENT_DATA_ACK)
                logger.debug(f"{lp} Received {data_len} bytes in {(_e - _s):.5f} s\nRAW: {data}\nINT: "
                             f"{bytes2list(data)}\nHEX: {data.hex()}")


        except Exception as e:
            logger.error(f"{lp} Exception in receive_task: {e}", exc_info=True)

    def dump_msgs(self):
        if self.dumped_msgs is False:
            logger.debug(f"Dumping messages for {self.address} to file")
            # sort messages by key
            msgs = dict(sorted(self.msgs.items(), key=lambda item: item[0]))
            try:
                with open(f"msgs_{self.address}.json", "w") as f:
                    f.write(json.dumps(msgs, indent=4) + "\n")
            except Exception as e:
                logger.error(f"Error writing messages to file: {e}")
            else:
                self.dumped_msgs = True
        else:
            logger.debug(f"Messages for {self.address} already dumped")

    def __init__(
        self,
        reader,
        writer,
        address: Optional[str] = None,
        _id: Optional[int] = None,
    ):
        self.buffers = {}
        self.dumped_msgs: bool = False
        if address is None and _id is None:
            raise ValueError("Address or ID must be provided to CyncDevice constructor")
        # IP address of WiFi device
        self.address: Optional[str] = address
        # MAC address of device (Same for BT/WiFi)
        self.mac: Optional[str] = None
        # id is used to send to a different device via BTLE mesh
        self.id: Optional[int] = _id
        self.read_lock = asyncio.Lock()
        self.write_lock = asyncio.Lock()

        self.reader: asyncio.StreamReader = reader
        self.writer: asyncio.StreamWriter = writer

        self.device_type: Optional[DeviceType] = None

        # BT/WiFi OR BT only device
        self.wifi: bool = True
        if self.address is None:
            logger.debug("Device is BT only, based on address being None")
            self.wifi = False

        # state: 0:off 1:on
        self._state: int = 0
        # 0-100
        self.brightness: int = 0
        # 0-100 (warm to cool)
        self.temperature: int = 0
        # 0-255
        self.r: int = 0
        self.g: int = 0
        self.b: int = 0
        # 0-255, 0: full saturation 255: no saturation (white)
        self.saturation: int = 0

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, value: Union[int, bool, str]):
        """Set the state of the device. Accepts int, bool, or str. 0, 'f', 'false', 'off', 'no', 'n' are off. 1, 't', 'true', 'on', 'yes', 'y' are on."""
        _t = (1, "t", "true", "on", "yes", "y")
        _f = (0, "f", "false", "off", "no", "n")
        if isinstance(value, str):
            value = value.casefold()
        elif isinstance(value, (bool, float)):
            value = int(value)
        else:
            raise TypeError(f"Invalid type for state: {type(value)}")

        if value in _t:
            value = 1
        elif value in _f:
            value = 0
        else:
            raise ValueError(f"Invalid value for state: {value}")

        self._state = value

    @property
    def rgb(self):
        """Return the RGB color as a list"""
        return [self.r, self.g, self.b]

    @property
    def rgba(self):
        """Return the RGB color and the saturation as a list"""
        return [self.r, self.g, self.b, self.saturation]

    async def read(self, chunk: Optional[int] = None):
        """Read data from the device if there is an open connection"""
        while self.reader:
            if chunk is None:
                chunk = 1024
            async with self.read_lock:
                return await self.reader.read(chunk)

                # return await self.reader.readline()

    async def write(self, data: bytes):
        if self.writer:
            async with self.write_lock:
                self.writer.write(data)
                await self.writer.drain()

    async def close(self):
        logger.debug(f"{self} close() called")
        self.dump_msgs()
        try:
            for task in self.tasks:
                if task is not None:
                    if task.done():
                        continue
                    logger.debug("%s Cancelling task: %s" % (self.lp, task))
                    task.cancel()
        except Exception as e:
            logger.error("%s Error stopping tasks: %s" % (self, e))

        if self.writer:
            async with self.write_lock:
                self.writer.close()
                await self.writer.wait_closed()
            self.writer = None

        if self.reader:
            self.reader.feed_eof()
            self.reader = None

    def __repr__(self):
        return f"<CyncDevice : {self.address}>"

    def __str__(self):
        return f"CyncDevice: {self.address}"


class CyncLanServer:
    """A class to represent a Cync LAN server that listens for connections from Cync WiFi devices.
    The WiFi devices can proxy messages to BlueTooth devices. The WiFi devices act as hubs for the BlueTooth mesh.
    """

    shutting_down: bool = False
    devices: dict = {}
    host: str
    port: int
    certfile: Optional[str] = None
    keyfile: Optional[str] = None
    loop: Union[asyncio.AbstractEventLoop, uvloop.Loop]
    thread_pool: Optional[ThreadPoolExecutor] = None
    _server: Optional[asyncio.Server] = None
    lp: str = "CyncLanServer:"
    socket: Optional[ssl.SSLSocket] = None

    def __init__(
        self,
        host: str,
        port: int,
        certfile: Optional[str] = None,
        keyfile: Optional[str] = None,
    ):
        self.ssl_context: Optional[ssl.SSLContext] = None
        self.socket = None
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.loop: uvloop.Loop = asyncio.get_event_loop()
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(4)

    async def create_ssl_context(self):
        # Allow the server to use a self-signed certificate
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        # turn off all the SSL verification
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
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
            logger.debug(f"Cync LAN server started on {self.host}:{self.port}")
            try:
                async with self._server:
                    await self._server.serve_forever()
            except asyncio.CancelledError as ce:
                logger.debug(f"{self.lp} Server cancelled (task.cancel() ?): {ce}")
            except Exception as e:
                logger.error(f"{self.lp} Server error: {e}")

            logger.info(f"{self.lp} end of start()")

    async def stop(self):
        logger.debug("%s stop() called, closing each device..." % self.lp)
        # check tasks
        devices = list(self.devices.values())
        if devices:
            for device in devices:
                try:
                    await device.close()
                except Exception as e:
                    logger.error(f"{self.lp} Error closing device: {e}")
                else:
                    logger.debug(f"{self.lp} Closed device: {device}")
                finally:
                    self.devices.pop(device.address)
        else:
            logger.debug(f"{self.lp} No devices to close!")

        if self._server:
            if self._server.is_serving():
                logger.debug("%s currently running, shutting down NOW..." % self.lp)
                self.shutting_down = True
                self._server.close()
                await self._server.wait_closed()
                logger.debug("%s shut down!" % self.lp)
            else:
                logger.debug("%s not running!" % self.lp)

        # used loop.run_until_complete, so signal we are complete
        for task in global_tasks:
            if task.done():
                continue
            logger.debug("%s Cancelling task: %s" % (self.lp, task))
            task.cancel()
        logger.debug("%s stop() complete, calling loop.stop()" % self.lp)
        self.loop.stop()

    async def _register_new_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        global global_tasks
        client_addr = writer.get_extra_info("peername")[0]
        logger.debug(f"{self.lp} New connection from: {client_addr}")
        # wrap the socket with SSL
        # read the first 5 bytes to determine the message type
        # Check if the device is already registered, if so, close the connection and replace
        existing_device: Optional[CyncDevice] = None
        if client_addr in self.devices:
            logger.warning(
                f"{self.lp} Device already registered for {client_addr}, replacing..."
            )
            existing_device = self.devices[client_addr]
            try:
                existing_device.writer.close()
                await existing_device.writer.wait_closed()
                existing_device.reader.feed_eof()
            except ConnectionError as ce:
                logger.error(f"{self.lp} Error closing existing connection: {ce}")
            except ConnectionResetError as cre:
                logger.error(f"{self.lp} Error closing existing connection: {cre}")
            existing_device.writer = None
            existing_device.reader = None
            # set new reader and writer
            existing_device.reader = reader
            existing_device.writer = writer

        create_task = False
        if existing_device is not None:
            device = existing_device
            # check if the receive task is running or in done or exception state.
            if device.tasks.device_receive is not None:
                if device.tasks.device_receive.done():
                    logger.debug(
                        f"{self.lp} Device receive task is done(), creating new task..."
                    )
                    create_task = True

        else:
            logger.debug(f"{self.lp} Creating new device for {client_addr}")
            device = CyncDevice(reader, writer, address=client_addr)
            create_task = True

        if create_task is True:
            # register async tasks to handle data rx
            rcv_task = self.loop.create_task(
                device.receive_task(client_addr),
            )
            device.tasks.device_receive = rcv_task
            global_tasks.append(rcv_task)

        self.devices[client_addr] = device


class LostConnection(Exception):
    pass


class ShuttingDown(Exception):
    pass


class CyncLAN:
    loop: uvloop.Loop = None
    mqtt: client.MQTTClient = None
    server: CyncLanServer = None
    lp: str = "CyncLAN:"

    def __init__(self):
        self.loop = uvloop.new_event_loop()
        if DEBUG is True:
            self.loop.set_debug(True)
        asyncio.set_event_loop(self.loop)

    def start(self):
        global global_tasks
        self.server = CyncLanServer(TLS_HOST, TLS_PORT, CYNC_CERT, CYNC_KEY)
        task = self.loop.create_task(self.server.start())
        global_tasks.append(task)
        asyncio.gather(task, return_exceptions=True)

    def stop(self):
        global global_tasks
        logger.debug(f"{self.lp} stop() called, calling server.stop()...")
        if self.server:
            task = self.loop.create_task(self.server.stop())
            global_tasks.append(task)
            asyncio.gather(task, return_exceptions=True)

    def signal_handler(self, sig: int):
        logger.info("Caught signal %d, trying a clean shutdown" % sig)
        self.stop()
        logger.debug("END OF SIGNAL HANDLER")


if __name__ == "__main__":
    global_tasks = []
    cync = CyncLAN()
    loop: uvloop.Loop = cync.loop
    logger.debug("Setting up event loop signal handlers")
    loop.add_signal_handler(signal.SIGINT, partial(cync.signal_handler, signal.SIGINT))
    loop.add_signal_handler(
        signal.SIGTERM, partial(cync.signal_handler, signal.SIGTERM)
    )
    try:
        cync.start()
        logger.debug("\nAfter cync.start()\n")
        cync.loop.run_forever()
        # logger.debug("\nAfter run_forever()\n")
    except KeyboardInterrupt as ke:
        logger.info("Caught KeyboardInterrupt in exception block!")
        raise ke

    except Exception as e:
        logger.warning(
            "Caught exception in __main__ cync.start() try block: %s" % e, exc_info=True
        )
    finally:
        if cync and not cync.loop.is_closed():
            logger.debug("Closing loop...")
            cync.loop.close()

    logger.debug(f"END OF __main__")


"""
aa = incremented everytime it reports or is called per device?
bb = brightness
ccc = UNKNOWN (checksum?) 117/137
xx = only changes when a diff device
Same device as connected to Brightness:
schema  (???, ?, ?, ?, xx, ??, ???, ???, ???, ?, aa, ?, ???, ?, ?, ?, ?, ???, ???, ??, ?, aa, ??, ??, ?, ?, ?, ?, ???, ??, ?, ?, ?, bb,  ?, ?, ???, ???, ?, ?, ccc, ???, ??, ?, ?, ?, ??, ??, ???, ???, ???, ?, ?, ?, ?, ?, ??, ?, ?, bb,  ?, ?, ???, ???, ?, ?, ?, ?, ?, ?, ?, ?, ?)
81% =>  (131, 0, 0, 0, 37, 57, 135, 166, 214, 0, 23, 0, 126, 0, 0, 0, 0, 250, 219, 19, 0, 67, 34, 17, 8, 0, 8, 0, 219, 17, 2, 1, 1, 81,  2, 0, 255, 191, 0, 0, 117, 126, 67, 0, 0, 0, 26, 57, 135, 166, 214, 1, 1, 6, 5, 0, 16, 8, 1, 81,  2, 0, 255, 191, 1, 0, 8, 0, 0, 0, 0, 0, 0)
100% => (131, 0, 0, 0, 37, 57, 135, 166, 214, 0, 24, 0, 126, 0, 0, 0, 0, 250, 219, 19, 0, 68, 34, 17, 8, 0, 8, 0, 219, 17, 2, 1, 1, 100, 2, 0, 255, 191, 0, 0, 137, 126, 67, 0, 0, 0, 26, 57, 135, 166, 214, 1, 1, 6, 5, 0, 16, 8, 1, 100, 2, 0, 255, 191, 1, 0, 8, 0, 0, 0, 0, 0, 0)
Same On/Off

"""
# [0:12] - First request has some sort of identifying data starting at index 12
APP_FIRST_REQ = b'\x13\x00\x00\x00+\x03-\xe4\xb5\xd2\x00\x10'
APP_FIRST_RESP = b'\x18\x00\x00\x00\x02\x00\x00'
# Some sort of challenge, index 5, 8 are dynamic
APP_SECOND_REQ = b'\xa3\x00\x00\x00\x077\x96\x13/\xd7\xdd\x00'
APP_SECOND_REPLY = b'\xab\x00\x00\x03\xfb7\x96\x1eL\xd7\xf7\x00\x07\x00\txlink_dev\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe3O\x02\x10'

APP_THIRD_REQ =  b'\xa3\x00\x00\x00\x077\x96\x1eL\xd7\xf7\x00'
APP_THIRD_REPLY = b'\xab\x00\x00\x03\xfb7\x96\x1eL\xd7\xf7\x00\x07\x00\txlink_dev\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe3O\x02\x10'


# 2nd reply first bytes
'ab 00 00 03 fb 37 96 1e 4c d7 f7 00 07 00 09 78'
# 3rd reply first bytes
'ab 00 00 03 fb 37 96 13 2f d7 f6 00 07 00 09 78'
'''
ab 00 00 03 fb 37 96 1e 4c d7 f7 00 07 00 09 78
6c 69 6e 6b 5f 64 65 76 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 e3 4f 02 10
'''

"""
# phone requested turn on id: 1
< from phone to server
> from server to phone
# phone sends 3 packets
< 2024/02/21 14:47:43.000713933  length=31 from=3172 to=3202
HEX: 43 00 00 00 1a 37 96  24 69  01 01 06 06 00 10 01 01 2c fe  e0 00 00 01 ff 05 00 00 00 00 00 00     
INT: 67 00 00 00 26 55 150 36 105  1  1  6  6  0 16  1  1 44 254 224 0  0  1 255 5  0  0  0  0  0  0

--
< 2024/02/21 14:47:43.000819708  length=42 from=3203 to=3244
 b'\x83\x00\x00\x00%7\x96\x13/\x031\x00~\x17\x00\x00\x00\xfa\xdb\x13\x00\xba$\x11\x01\x00\x01\x00\xdb\x11\x02\x01\x01,\xfe\xe0\x00\x00\x00\x00\xd9~'
HEX: 83 00 00 00 25 37 96  13 2f 03 31 00 7e  17 00 00 00 fa  db  13 00 ba  24 11 01 00 01 00 db  11 02 01 01 2c fe  e0  00 00 00 00 d9  7e
INT: 131 0  0  0 37 55 150 19 47  3 49  0 126 23  0  0  0 250 219 19  0 186 36 17  1  0  1  0 219 17  2  1  1 44 254 224  0  0  0  0 217 126                  
--
< 2024/02/21 14:47:43.000821770  length=31 from=3245 to=3275
 43 00 00 00 1a 37 96 13 2f 01 01 06 06 00 10 01 01 2c fe e0 00 00 01 ff 06 00 00 00 00 00 00   
--
# server replies
> 2024/02/21 14:47:43.000884001  length=12 from=518 to=529
 7b 00 00 00 07 37 96 13 2f 03 31 00              {....7../.1.
--
"""