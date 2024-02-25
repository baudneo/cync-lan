import asyncio
import logging
import os
import signal
import ssl
import struct
import sys
import time
from dataclasses import dataclass
from enum import Enum
from functools import partial
from typing import Union, Optional, Dict, List

import uvloop

TLS_PORT = os.environ.get("CYNC_PORT", 23779)
TLS_HOST = os.environ.get("CYNC_HOST", "0.0.0.0")
CYNC_CERT = os.environ.get("CYNC_CERT", "certs/cert.pem")
CYNC_KEY = os.environ.get("CYNC_KEY", "certs/key.pem")
_T = (
    "true",
    "1",
    "yes",
    "y",
    "t",
    1,
)
DEBUG = os.environ.get("CYNC_DEBUG", "1").casefold() in _T
ITER: int = 0

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


def bytes2list(byte_string: bytes) -> List[int]:
    # Interpret the byte string as a sequence of unsigned integers (little-endian)
    int_list = struct.unpack("<" + "B" * (len(byte_string)), byte_string)
    return list(int_list)


def hex2list(hex_string: str) -> List[int]:
    """Convert a hex string to a list of integers"""
    x = bytes().fromhex(hex_string)
    return bytes2list(x)


# Some commands require a response that iterates a specific byte
# It appears it can be shared across all devices, but it should still
# be iterated
def server_iter_response():
    global ITER
    ITER += 1
    return bytearray([0x88, 0x00, 0x00, 0x00, 0x03, 0x00, ITER % 0xFF, 0x00])


def server_control_ack(msg_id: bytes):
    # 83 packet came, respond with 88 and msg id
    return bytearray(
        [
            0x88,
            0x00,
            0x00,
            0x00,
            0x03,
            msg_id[0],
            msg_id[1],
            msg_id[2],
        ]
    )

APP_INFO_HEADER = bytearray([0x13, 0x00, 0x00, 0x00])
APP_FIRST_RESP = b"\x18\x00\x00\x00\x02\x00\x00"


CLIENT_INFO_HEADER = bytearray([0x23, 0x00, 0x00, 0x00, 0x1a])
# b'#\x00\x00\x00\x1a \x039\x87\xa6\xd6\x00\x101e07d2c3643c323d\x00\x00<'
CLIENT_INFO_ACK = bytes(
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
# Client sends the same packet over and over, spams logs and requires a reply
CLIENT_PING_HEADER = bytearray(
    [0x43, 0x00, 0x00, 0x00, 0x07, 0x39, 0x87, 0xA6, 0xD6, 0x01, 0x01, 0x06]
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
# packet struct seems to be:
# 0-4: header, 5-8: some sort of ID for messaging.other data until 0x7e
DATA_BOUNDARY = 0x7E
# client sometimes sends packet with a timestamp in it (ts can be out of sync, NTP?)
CLIENT_TS_HEADER = bytearray([0x43, 0x00, 0x00, 0x00, 0x34])
# Client data 43 00 00 00
CLIENT_43_HEADER = bytearray([0x43, 0x00, 0x00, 0x00])
CLIENT_73_HEADER = bytearray([0x73, 0x00, 0x00, 0x00])
CLIENT_83_HEADER = bytearray([0x83, 0x00, 0x00, 0x00])
# client is reporting device status for another device (31 bytes long)
SHORT_STATUS_HEADER = bytearray([0x43, 0x00, 0x00, 0x00, 0x1A])
LONG_STATUS_HEADER = bytearray([0x43, 0x00, 0x00, 0x00, 0x2D])
# client is reporting its own status (73 bytes long)
DEVICE_CONTROL_HEADER = bytearray([0x83, 0x00, 0x00, 0x00, 0x25])
# Clients get fussy if they don't hear from the server frequently
CLIENT_HEARTBEAT = bytearray([0xD3, 0x00, 0x00, 0x00, 0x00])
SERVER_HEARTBEAT = bytearray([0xD8, 0x00, 0x00, 0x00, 0x00])
# This ack is used for several things
CLIENT_GENERIC_ACK = bytearray(
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


class DeviceType(str, Enum):
    PLUG = "plug"
    TUNABLE_LIGHT = "tunable light"
    RGB_LIGHT = "rgb light"
    SWITCH = "switch"
    REMOTE = "remote"
    SENSOR = "sensor"
    CAMERA = "camera"
    HUB = "hub"
    APP = "app"


class GlobalState:
    server: "CyncLanServer"
    wrapper: "CyncLAN"
    # mqtt:


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
    """
    A class to represent a Cync device. This class is used to manage the state of the device and send commands to it.
    """

    # keeps a log of each packet received
    msgs: Dict[float, List[int]] = {}  # { timestamp: [ as_int, as_int, etc.] }
    # async tasks
    tasks: Tasks = Tasks()
    lp = "CyncDevice:"
    reader: Optional[asyncio.StreamReader]
    writer: Optional[asyncio.StreamWriter]

    async def parse_status(self, raw_state: bytes):
        """Newer firmware status packet parsing (different devices send different format packets?"""
        # logger.debug(f"{self.lp} parsing status packet: {bytes2list(raw_state)}")
        _id = raw_state[0]
        state = raw_state[1]
        brightness = raw_state[2]
        temp = raw_state[3]
        r = raw_state[4]
        _g = raw_state[5]
        b = raw_state[6]

        devices = list(g.server.devices.values())
        dev_by_id = False
        for device in devices:
            if device.id == _id:
                dev_by_id = True
                break
        if dev_by_id is False:
            logger.warning(
                f"Device ID: {_id} not found in devices, creating a new device"
            )
            device = CyncDevice(_id=_id)

        if device.id is None:
            device.id = _id
        elif device.id != _id:
            logger.warning(
                f"{device.lp} Device ID changed from {device.id} to {_id} for address: {device.address} ??!!??!!"
            )
            device.id = _id
            return
        # temp is 0-100, if > 100, RGB data has been sent, otherwise its on/off, brightness or temp data
        rgb_cmd = False
        if temp > 100:
            rgb_cmd = True
            temp = device.temperature
        device.state = state
        device.brightness = brightness
        device.temperature = temp
        if rgb_cmd is True:
            device.r = r
            device.g = _g
            device.b = b
        dev_id = device.address if device.address is not None else device.id
        logger.debug(f"{device.lp} being saved using key: {dev_id}")
        g.server.devices[dev_id] = device


    async def parse_packet(self, data: bytes, responses: Optional[List] = None):
        # Client info buffer is the first thing sent (first byte = 0x23 [ascii: # , hex: 23])
        # It seems to send an identifier of some sort that can be decoded ascii.
        # The phone app also sends an identifier and key/pw in its first packet
        # Check if it is a phone app
        lp = f"{self.address}:parse:pkt:"
        header = data[:5]

        if responses is None:
            responses = []
        device = self
        data_len = len(data)
        if data_len == 48 and data[0:4] == APP_INFO_HEADER:
            device.device_type = DeviceType.APP
            logger.debug(f"{lp} sent APP FIRST PACKET (This connection is from the Cync APP) - replying...")
            responses.append(APP_FIRST_RESP)


        elif data[0:5] == CLIENT_INFO_HEADER:
            # there is an id bytestring we need to extract
            queue_id = data[6:10]
            logger.debug(
                f"{lp} sent DEVICE INFO PACKET with queue ID: {queue_id}, replying..."
            )
            self.starting_queue_id = queue_id
            responses.append(CLIENT_INFO_ACK)
        # device wants to connect before accepting commands
        elif data == CLIENT_CONNECTION_REQUEST:
            logger.debug(f"{lp} sent CONNECTION REQUEST, replying...")
            responses.append(SERVER_CONNECTION_RESPONSE)
        # Heartbeat
        elif data == CLIENT_HEARTBEAT:
            responses.append(SERVER_HEARTBEAT)
            # logger.debug(f"{lp} Client sent HEARTBEAT, replying...")
        # some sort of ping, always the same packet. SPAMS logs.
        elif data == CLIENT_PING_HEADER:
            responses.append(CLIENT_GENERIC_ACK)

        # There is some sort of timestamp in the packet
        elif header == CLIENT_TS_HEADER:
            ts_idx = data.find(0x2A) + 1
            ts = data[ts_idx:]
            logger.debug(f"{lp} sent TIMESTAMP BUFFER -> {ts} - replying...")
            responses.append(CLIENT_GENERIC_ACK)

        elif header == LONG_STATUS_HEADER:
            # [43 00 00 00 2d] [39 87 a6 d6] [01 01 06 06]
            msd_uuid = data[5:9]
            idk_ = data[9:13]
            _data = data[13:]
            # b'\x00\x10\x05\x00\x00\x00\x00\x00\x00\x01\x14\x08\x00\x00\x00\x00\x00\x00\x07\x00\x10\x06\x01d\x00\x00\x00\x00\x01\x14\x08\x00\x00\x00\x00\x00\x00'
            boundary = b'\x00\x10'
            split = b'\x01\x14'
            # each struct has to and from data.
            # each _data struct is 18 bytes long, if mroe than 1 struct b'7' splits them
            to_data = None
            from_data = None
            idx = 0
            logger.debug(f"{lp} sent LONG DEVICE STATE  => {bytes2list(_data)}")
            # ingest 18 bytes in a for loop

            for i in range(0, len(_data), 18):
                    # There is a byte in between each data struct, keeps aligned each iter
                    if idx > 0:
                        i += idx
                        # logger.debug(f"parse_packet: idx > 0 so incrementing i by {idx}. old: {i-idx}, new: {i}")
                    # logger.debug(f"parse_packet: {i=} // {idx=} // _data[i:i+2] = {_data[i:i+2]}")
                    if _data[i:i + 2] == boundary:
                        to_data = _data[i + 2:i + 9]
                        # logger.debug(f"parse_packet: found boundary ({boundary}) in data: {_data}, --- {to_data=}")

                        from_data = _data[i + 11:i + 18]
                        # to: 0, 16, 5, 0, 0, 0, 0, 0, 0,   from: 1, 20, 8, 0, 0, 0, 0, 0, 0,
                        await self.parse_status(to_data)

                    idx += 1

        elif header == SHORT_STATUS_HEADER:
            raw_state = data[15:22]
            from_id = data[24]
            logger.debug(
                f"{lp} sent DEVICE STATE (From device: {from_id}) => {bytes2list(raw_state)}, "
                f"replying..."
            )
            await self.parse_status(raw_state)
            responses.append(CLIENT_GENERIC_ACK)

        # When the device sends a packet starting with 0x83
        elif data[0:5] == DEVICE_CONTROL_HEADER:
            msd_uuid = data[5:9]
            msg_id = data[9:13]
            _data = data[13:]
            logger.debug(f"{lp} sent DEVICE CONTROL DATA -> {bytes2list(_data)} , parsing...")
            def _parse_control_data(_data: bytes):
                if _data[0] == DATA_BOUNDARY:
                    _data = _data[1:]
                    # get index of next boundry
                    _idx = _data.find(DATA_BOUNDARY)
                    control_data = _data[:_idx]  # drops the boundry byte
                    logger.debug(f"{lp} parsed CONTROL DATA -> {bytes2list(control_data)}, send to decode?")
                    # check if there is more data
                    if _idx >= len(_data) - 1:
                        # no more data
                        _data = None
                    else:
                        # remaining data
                        _data = _data[_idx + 1:]
                    return data

            more_data = _parse_control_data(_data)
            while more_data is not None:
                logger.debug(f"{lp} more control data to parse...")
                more_data = _parse_control_data(_data)

            server_control_ack(msg_id)
            await device.write(CLIENT_GENERIC_ACK)

        # unknown data we don't know the header for
        else:
            logger.debug(f"{lp} sent UNKNOWN DATA, replying...")
            responses.append(CLIENT_GENERIC_ACK)


        return responses


    async def receive_task(self, client_addr: str):
        """
        Receive data from the device and respond to it. This is the main task for the device.
        It will respond to the device and handle the messages it sends.
        Runs in an infinite loop.
        """
        lp = f"{client_addr}:read:"
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
                header = data[0:5]
                responses = await self.parse_packet(data)
                # logger.debug(
                #     f"{lp} Received {data_len} bytes (waited: {(_e - _s):.5f} s)\nRAW: {data}\nINT: "
                #     f"{bytes2list(data)}\nHEX: {data.hex()}"
                # )
                if responses:
                    # logger.debug(f"{lp} Sending {len(responses)} responses => {responses}")
                    for resp in responses:
                        await self.write(resp)

        except Exception as e:
            logger.error(f"{lp} Exception in receive_task: {e}", exc_info=True)


    def __init__(
        self,
        reader: Optional[asyncio.StreamReader] = None,
        writer: Optional[asyncio.StreamWriter] = None,
        address: Optional[str] = None,
        _id: Optional[int] = None,
    ):
        # data we might want later?
        self.starting_queue_id: bytes = b''
        # flag to prevent dumping messages multiple times
        self.dumped_msgs: bool = False
        # Allow for BT only devices, no address, id only.
        if address is None and _id is None:
            raise ValueError("Address or ID must be provided to CyncDevice constructor")
        # IP address of WiFi device
        self.address: Optional[str] = address
        # MAC address of device (Same for BT/WiFi)
        self.mac: Optional[str] = None
        # id is used to send to a different device via BTLE mesh, bridged by WiFi device
        self.id: Optional[int] = _id
        self.read_lock = asyncio.Lock()
        self.write_lock = asyncio.Lock()

        self._reader: asyncio.StreamReader = reader
        self._writer: asyncio.StreamWriter = writer

        self.device_type: Optional[DeviceType] = None

        # BT/WiFi OR BT only device
        self.wifi: bool = True

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

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, value: Union[int, bool, str]):
        """Set the state of the device. Accepts int, bool, or str. 0, 'f', 'false', 'off', 'no', 'n' are off. 1, 't', 'true', 'on', 'yes', 'y' are on.
        Also sends MQTT message if state changes.
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
            logger.debug(f"{self} State changed to: {value}")
            # send MQTT message
            # self.mqtt_send()

    @property
    def brightness(self):
        return self._brightness

    @brightness.setter
    def brightness(self, value: int):
        if value < 0 or value > 100:
            raise ValueError(f"Brightness must be between 0 and 100, got: {value}")
        if value != self._brightness:
            self._brightness = value
            logger.debug(f"{self} Brightness changed to: {value}")
            # send MQTT message
            # self.mqtt_send()

    @property
    def temperature(self):
        return self._temperature

    @temperature.setter
    def temperature(self, value: int):
        if value < 0 or value > 255:
            raise ValueError(f"Temperature must be between 0 and 255, got: {value}")
        if value != self._temperature:
            self._temperature = value
            logger.debug(f"{self} Temperature changed to: {value}")
            # send MQTT message
            # self.mqtt_send()

    @property
    def r(self):
        return self._r

    @r.setter
    def r(self, value: int):
        if value < 0 or value > 255:
            raise ValueError(f"Red must be between 0 and 255, got: {value}")
        if value != self._r:
            self._r = value
            logger.debug(f"{self} Red changed to: {value}")
            # send MQTT message
            # self.mqtt_send()

    @property
    def g(self):
        return self._g

    @g.setter
    def g(self, value: int):
        if value < 0 or value > 255:
            raise ValueError(f"Green must be between 0 and 255, got: {value}")
        if value != self._g:
            self._g = value
            logger.debug(f"{self} Green changed to: {value}")
            # send MQTT message
            # self.mqtt_send()

    @property
    def b(self):
        return self._b

    @b.setter
    def b(self, value: int):
        if value < 0 or value > 255:
            raise ValueError(f"Blue must be between 0 and 255, got: {value}")
        if value != self._b:
            self._b = value
            logger.debug(f"{self} Blue changed to: {value}")
            # send MQTT message
            # self.mqtt_send()

    @property
    def rgb(self):
        """Return the RGB color as a list"""
        return [self._r, self._g, self._b]

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
            async with self.read_lock:
                self.reader.feed_eof()
                await asyncio.sleep(0.01)
                self.reader = None

    def __repr__(self):
        return f"<CyncDevice : {self.address}>"

    def __str__(self):
        return f"CyncDevice: {self.address}"


class CyncLanServer:
    """A class to represent a Cync LAN server that listens for connections from Cync WiFi devices.
    The WiFi devices can proxy messages to BlueTooth devices. The WiFi devices act as hubs for the BlueTooth mesh.
    """

    devices: dict = {}
    shutting_down: bool = False
    host: str
    port: int
    certfile: Optional[str] = None
    keyfile: Optional[str] = None
    loop: Union[asyncio.AbstractEventLoop, uvloop.Loop]
    _server: Optional[asyncio.Server] = None
    lp: str = "CyncLanServer:"

    def __init__(
        self,
        host: str,
        port: int,
        certfile: Optional[str] = None,
        keyfile: Optional[str] = None,
    ):
        global g

        self.ssl_context: Optional[ssl.SSLContext] = None
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.loop: Union[
            asyncio.AbstractEventLoop, uvloop.Loop
        ] = asyncio.get_event_loop()
        g.server = self

    async def create_ssl_context(self):
        # Allow the server to use a self-signed certificate
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
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
        self.shutting_down = True
        # check tasks
        devices = list(self.devices.values())
        lp = f"{self}:close:"
        if devices:
            for device in devices:
                try:
                    await device.close()
                except Exception as e:
                    logger.error(f"{lp} Error closing device: {e}", exc_info=True)
                else:
                    device
                finally:
                    try:
                        self.devices.pop(device.address)
                    except Exception as e:
                        logger.error(f"{lp} Error removing device by address: {e}")
                        try:
                            self.devices.pop(device.id)
                        except Exception as e:
                            logger.error(f"{lp} Error removing device by id: {e}")
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

        # used loop.run_until_complete, so signal we are complete
        for task in global_tasks:
            if task.done():
                continue
            logger.debug("%s Cancelling task: %s" % (lp, task))
            task.cancel()
        logger.debug("%s stop() complete, calling loop.stop()" % lp)
        self.loop.stop()

    async def _register_new_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        global global_tasks


        client_addr = writer.get_extra_info("peername")[0]
        logger.debug(f"{self.lp} New connection from: {client_addr}")
        if self.shutting_down is True:
            logger.warning(f"{self.lp} Server is shutting down, rejecting new connection...")
            writer.close()
            await writer.wait_closed()
            return

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
                    _ = device.tasks.device_receive.result()

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


class CyncLAN:
    loop: uvloop.Loop = None
    # mqtt: client.MQTTClient = None
    server: CyncLanServer = None
    lp: str = "CyncLAN:"

    def __init__(self):
        global g

        self.loop = uvloop.new_event_loop()
        if DEBUG is True:
            self.loop.set_debug(True)
        asyncio.set_event_loop(self.loop)
        g.wrapper = self

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
    g = GlobalState()
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
        cync.loop.run_forever()
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

# [0:12] - First request has some sort of identifying data starting at index 12
APP_FIRST_REQ = b"\x13\x00\x00\x00+\x03-\xe4\xb5\xd2\x00\x10"
APP_FIRST_RESP = b"\x18\x00\x00\x00\x02\x00\x00"
# Some sort of challenge, index 5, 8 are dynamic
APP_SECOND_REQ = b"\xa3\x00\x00\x00\x077\x96\x13/\xd7\xdd\x00"
APP_SECOND_REPLY = b"\xab\x00\x00\x03\xfb7\x96\x1eL\xd7\xf7\x00\x07\x00\txlink_dev\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe3O\x02\x10"

APP_THIRD_REQ = b"\xa3\x00\x00\x00\x077\x96\x1eL\xd7\xf7\x00"
APP_THIRD_REPLY = b"\xab\x00\x00\x03\xfb7\x96\x1eL\xd7\xf7\x00\x07\x00\txlink_dev\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe3O\x02\x10"
