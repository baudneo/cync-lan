import asyncio
import datetime
import logging
import logging.handlers
import os
import random
import ssl
import struct
import sys
import time
from functools import partial
from pathlib import Path
from typing import Coroutine, Dict, List, Optional, Union

from cync_lan.const import (
    CYNC_CLOUD_IP,
    CYNC_CMD_BROADCASTS,
    CYNC_LOG_NAME,
    CYNC_MAX_TCP_CONN,
    CYNC_MITM_LOG_DIR,
    CYNC_MITM_DEV_LOGGER,
    CYNC_RAW,
    CYNC_TCP_WHITELIST,
    DATA_BOUNDARY,
    FACTORY_EFFECTS_BYTES,
    RAW_MSG,
    STREAM_CHUNK_SIZE,
    TCP_BLACKHOLE_DELAY, CYNC_MITM_APP_LOGGER,
)
from cync_lan.metadata.model_info import (
    MULTI_ENDPOINT_TYPES,
    DeviceClassification,
    DeviceTypeInfo,
    device_type_map,
)
from cync_lan.packet import PacketBuilder
from cync_lan.structs import (
    CacheData,
    ControlMessageCallback,
    EntityState,
    FanSpeed,
    GlobalObject,
    MessageCache,
    Tasks,
)
from cync_lan.utils import bytes2list, extract_firmware_dynamically, format_socat_style

__all__ = ["CyncDevice", "CyncTCPSession"]
logger = logging.getLogger(CYNC_LOG_NAME)
g = GlobalObject()


class CyncDevice:
    """
    A class to represent a physical Cync device
    """

    lp = "CyncDevice:"
    id: int = None
    ip_address: str = None
    type: Optional[int] = None
    _supports_rgb: Optional[bool] = None
    _supports_temperature: Optional[bool] = None
    _is_light: Optional[bool] = None
    _is_switch: Optional[bool] = None
    _is_plug: Optional[bool] = None
    _is_fan_controller: Optional[bool] = None
    _is_hvac: Optional[bool] = None
    _mac: Optional[str] = None
    wifi_mac: Optional[str] = None
    hvac: Optional[dict] = None
    _online: bool = False
    metadata: Optional[DeviceTypeInfo] = None
    entities: Optional[Dict[int, EntityState]] = None
    last_valid_state_ts: float = 0
    num_late_states: int = 0
    mqtt_metadata = None
    tcp_session: Optional["CyncTCPSession"] = None

    def __init__(
        self,
        dev_id: int,
        dev_type: Optional[int] = None,
        name: Optional[str] = None,
        mac: Optional[str] = None,
        wifi_mac: Optional[str] = None,
        fw_version: Optional[str] = None,
        home_id: Optional[int] = None,
        hvac: Optional[dict] = None,
        entities: Optional[Dict[int, "EntityState"]] = None,
    ):
        self.control_bytes = bytes([0x00, 0x00])
        if dev_id is None:
            raise ValueError("ID must be provided to constructor")
        self.id = dev_id
        self.entities: Optional[Dict[int, "EntityState"]] = entities
        self.type = dev_type
        self.metadata: DeviceTypeInfo = (
            device_type_map[self.type] if dev_type in device_type_map else None
        )
        self.home_id: Optional[int] = home_id
        self._mac = mac
        self.wifi_mac = wifi_mac
        self._version: Optional[str] = None
        self.version = fw_version
        if name is None:
            name = f"device_{dev_id}"
        self.name = name
        self.lp = f"{self.name}({dev_id}):"
        if hvac is not None:
            self.hvac = hvac
            self._is_hvac = True

    @property
    def hass_id(self):
        return f"{self.home_id}-{self.id}"

    @property
    def is_sol_lamp(self) -> bool:
        """Return True for older XLink Wi-Fi-direct devices (e.g. C by GE Sol, type 80).

        These devices require 0xD2 for brightness and 0xE2 (sub-cmd 0x05) for CCT,
        rather than the 0xF0 opcodes used by newer Cync mesh devices.
        """
        return bool(self.metadata and self.metadata.opcodes.sol_lamp)

    @property
    def is_hvac(self) -> bool:
        if self._is_hvac is not None:
            return self._is_hvac
        if self.type is None:
            return False
        return (
            self.type in self.Capabilities["HEAT"]
            or self.type in self.Capabilities["COOL"]
            or self.type in self.DeviceTypes["THERMOSTAT"]
        )

    @is_hvac.setter
    def is_hvac(self, value: bool) -> None:
        if isinstance(value, bool):
            self._is_hvac = value

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
            if value == "":
                logger.debug(
                    f"{self.lp} in CyncDevice.version().setter, the firmwareVersion "
                    f"extracted from the cloud is an empty string!"
                )
            elif value.casefold() == "unknown":
                logger.debug(f"{self.lp} This is a sub-device")
            else:
                try:
                    _x = int(value.replace(".", "").replace("\0", "").strip())
                except ValueError as ve:
                    logger.exception(
                        f"{self.lp} Failed to convert firmware version to int: {ve}"
                    )
                else:
                    self._version = _x

    @property
    def mac(self) -> str:
        return str(self._mac) if self._mac is not None else None

    @mac.setter
    def mac(self, value: str) -> None:
        self._mac = str(value)

    @property
    def bt_only(self) -> bool:
        if self.wifi_mac == "00:01:02:03:04:05":
            return True
        if self.metadata:
            return self.metadata.protocol.TCP is False
        return False

    @property
    def has_wifi(self) -> bool:
        if self.metadata:
            return self.metadata.protocol.TCP
        return False

    @property
    def is_light(self):
        if self._is_light is not None:
            return self._is_light
        if self.metadata:
            self._is_light = self.metadata.type == DeviceClassification.LIGHT
        else:
            self._is_light = False
        return self._is_light

    @is_light.setter
    def is_light(self, value: bool) -> None:
        if isinstance(value, bool):
            self._is_light = value
        else:
            logger.error(
                f"{self.lp} is_light must be a boolean value, got {type(value)} instead"
            )

    @property
    def is_switch(self) -> bool:
        if self._is_switch is not None:
            return self._is_switch
        if self.metadata:
            return self.metadata.type == DeviceClassification.SWITCH
        return False

    @is_switch.setter
    def is_switch(self, value: bool) -> None:
        if isinstance(value, bool):
            self._is_switch = value
        else:
            logger.error(
                f"{self.lp} is_switch must be a boolean value, got {type(value)} instead"
            )

    @property
    def is_plug(self) -> bool:
        if self._is_plug is not None:
            return self._is_plug
        if self.metadata:
            if self.metadata.type == DeviceClassification.SWITCH:
                if self.metadata.capabilities:
                    return self.metadata.capabilities.plug
        return False

    @is_plug.setter
    def is_plug(self, value: bool) -> None:
        self._is_plug = value

    @property
    def has_multi_endpoints(self) -> bool:
        return len(self.entities) > 1

    @property
    def is_fan_controller(self):
        if self._is_fan_controller is not None:
            return self._is_fan_controller
        if self.metadata:
            if self.metadata.type == DeviceClassification.SWITCH:
                if self.metadata.capabilities:
                    return self.metadata.capabilities.fan
        return False

    @is_fan_controller.setter
    def is_fan_controller(self, value: bool) -> None:
        self._is_fan_controller = value

    @property
    def is_dimmable(self) -> bool:
        if self.metadata:
            if self.metadata.type == DeviceClassification.LIGHT:
                if self.metadata.capabilities:
                    return self.metadata.capabilities.dimmable
        return False

    @property
    def supports_rgb(self) -> bool:
        if self._supports_rgb is not None:
            return self._supports_rgb
        if self.metadata:
            if self.metadata.type == DeviceClassification.LIGHT:
                if self.metadata.capabilities:
                    return self.metadata.capabilities.color
        return False

    @supports_rgb.setter
    def supports_rgb(self, value: bool) -> None:
        self._supports_rgb = value

    @property
    def supports_temperature(self) -> bool:
        if self._supports_temperature is not None:
            return self._supports_temperature
        if self.metadata:
            if self.metadata.type == DeviceClassification.LIGHT:
                if self.metadata.capabilities:
                    return self.metadata.capabilities.tunable_white
        return False

    @supports_temperature.setter
    def supports_temperature(self, value: bool) -> None:
        self._supports_temperature = value

    @property
    def online(self):
        return self._online

    @online.setter
    def online(self, value: bool):
        if not isinstance(value, bool):
            raise TypeError(f"Online status must be a boolean, got: {type(value)}")
        if value != self._online:
            self._online = value
            g.tasks.append(
                asyncio.get_running_loop().create_task(
                    g.mqtt_client.pub_online(self.id, value)
                )
            )

    @property
    def state(self):
        # Lazy evaluation: Only runs next() if get(0) returns None.
        # The 'None' inside next() prevents StopIteration crashes.
        ep = self.entities.get(0) or next(iter(self.entities.values()), None)
        if not ep:
            return 0
        # Note: using ep.power based on your new EndpointState class
        return ep.power

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
            # Sol and some devices report state as 0-100 instead of 0/1
            # Treat any non-zero int as ON
            value = 1 if value > 0 else 0
        else:
            raise TypeError(f"Invalid type for state: {type(value)}")

        if value in _t:
            value = 1
        elif value in _f:
            value = 0
        else:
            raise ValueError(f"Invalid value for state: {value}")

        ep = self.entities.get(0) or next(iter(self.entities.values()), None)
        if not ep:
            logger.error(f"{self.lp} Cannot set state, self.endpoints is empty!")
            return

        if value != ep.power:
            ep.power = value

    @property
    def brightness(self):
        ep = self.entities.get(0, next(iter(self.entities.values())))
        return ep.brightness

    @brightness.setter
    def brightness(self, value: int):
        if value < 0 or value > 255:
            raise ValueError(f"Brightness must be between 0 and 255, got: {value}")
        ep = self.entities.get(0, next(iter(self.entities.values())))
        if value != ep.brightness:
            ep.brightness = value

    @property
    def temperature(self):
        ep = self.entities.get(0, next(iter(self.entities.values())))
        return ep.temperature

    @temperature.setter
    def temperature(self, value: int):
        if value < 0 or value > 255:
            raise ValueError(f"Temperature must be between 0 and 255, got: {value}")
        ep = self.entities.get(0, next(iter(self.entities.values())))
        if value != ep.temperature:
            ep.temperature = value

    @property
    def red(self):
        ep = self.entities.get(0, next(iter(self.entities.values())))
        return ep.red

    @red.setter
    def red(self, value: int):
        if value < 0 or value > 255:
            raise ValueError(f"Red must be between 0 and 255, got: {value}")
        ep = self.entities.get(0, next(iter(self.entities.values())))
        if value != ep.red:
            ep.red = value

    @property
    def green(self):
        ep = self.entities.get(0, next(iter(self.entities.values())))
        return ep.green

    @green.setter
    def green(self, value: int):
        if value < 0 or value > 255:
            raise ValueError(f"Green must be between 0 and 255, got: {value}")
        ep = self.entities.get(0, next(iter(self.entities.values())))
        if value != ep.green:
            ep.green = value

    @property
    def blue(self):
        ep = self.entities.get(0, next(iter(self.entities.values())))
        return ep.blue

    @blue.setter
    def blue(self, value: int):
        if value < 0 or value > 255:
            raise ValueError(f"Blue must be between 0 and 255, got: {value}")
        ep = self.entities.get(0, next(iter(self.entities.values())))
        if value != ep.blue:
            ep.blue = value

    @property
    def rgb(self):
        """Return the RGB color as a list"""
        ep = self.entities.get(0, next(iter(self.entities.values())))
        return [ep.red, ep.green, ep.blue]

    @rgb.setter
    def rgb(self, value: List[int]):
        if len(value) != 3:
            raise ValueError(f"RGB value must be a list of 3 integers, got: {value}")
        ep = self.entities.get(0, next(iter(self.entities.values())))
        if value != [ep.red, ep.green, ep.blue]:
            ep.red, ep.green, ep.blue = value

    def __repr__(self):
        return f"<CyncDevice: {self.id}>"

    def __str__(self):
        return f"CyncDevice:{self.id}:"

    async def handle_entity_update(
        self,
        e_state: EntityState,
        from_pkt: Optional[str] = None,
    ) -> bool:
        """Extracted status packet parsing, handles MQTT publishing and device state changes."""
        ts = time.time()
        is_recent = bool(e_state.recently_seen)
        sub_fmt_str = (
            " '{}' ({})".format(e_state.name, e_state.sub_id) if e_state.sub_id > 0 else ""
        )
        if not is_recent:
            if self.metadata is not None:
                if not self.metadata.supported:
                    return False

            # logger.debug(f"{self.lp}{sub_fmt_str} seems to have STALE data (no BT mesh activity)")
            self.num_late_states += 1
            tcp_count = len(g.ncync_server.tcp_connections) or 1
            # With one TCP node, stale data immediately marks offline.
            # With multiple TCP nodes, wait until stale reports match node count.
            should_mark_offline = tcp_count == 1 or self.num_late_states >= tcp_count
            if should_mark_offline:
                if self.online:
                    self.online = False
                    logger.warning(
                        f"{self.lp}{sub_fmt_str} marked OFFLINE "
                        f"(stale state count {self.num_late_states} / num tcp nodes {tcp_count})"
                    )
                else:
                    logger.warning(
                        f"{self.lp}{sub_fmt_str} is still marked as {'ONLINE' if self.online else 'OFFLINE'} -> "
                        f"(stale state count {self.num_late_states} / num tcp nodes {tcp_count})"
                    )
                return True

        if not self.online:
            logger.info(
                f"{self.lp}{" '{}' ({})".format(e_state.name, e_state.sub_id) if e_state.sub_id > 0 else ''} "
                f"is marked ONLINE."
            )
            self.online = True
        # valid states are used to gauge CyncLAN health, if no valid states are received within a configured time limit
        # the bridge device 'Should restart?' sensor will be turned on. Trying to catch an edge case where CyncLAN stalls
        g.last_valid_state_ts = self.last_valid_state_ts = ts
        self.num_late_states = 0
        self.entities[e_state.sub_id] = e_state
        g.ncync_server.node_devices[self.id] = self
        return await g.mqtt_client.parse_entity_state(e_state, from_pkt=from_pkt)

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

    async def send_command(self, op: int, sub_id: int, payload: bytes, m_cb: ControlMessageCallback, lp: str):
        tasks = []
        tcp_pool = [d for d in g.ncync_server.tcp_connections.values() if not d.is_app]
        if not tcp_pool:
            logger.debug(f"{lp} no eligible TCP connections available for command broadcast")
            return

        tcp_connections: List["CyncTCPSession"] = random.sample(
            tcp_pool,
            k=min(CYNC_CMD_BROADCASTS, len(tcp_pool)),
        )
        for bridge_device in tcp_connections:
            if bridge_device.ready_to_control or bridge_device.mitm_mode:
                cmsg_id = bridge_device.get_ctrl_msg_id_bytes()[0]

                inner_pkt = PacketBuilder.build_control_packet(
                    msg_id=cmsg_id,
                    target_id=self.id,
                    sub_id=sub_id,
                    op_code=op,
                    command_payload=payload
                )

                full_packet = PacketBuilder.build_outer_packet(
                    packet_type=0x73,
                    queue_id=bridge_device.queue_id,
                    inner_packet=inner_pkt
                )
                m_cb.id = cmsg_id
                m_cb.message = full_packet
                m_cb.sent_at = time.time()
                bridge_device.messages.control[cmsg_id] = m_cb
                if bridge_device.mitm_mode is True:
                    logger.debug(
                        f"{lp} MITM mode active for this device: {bridge_device.ip_address} (ID: {bridge_device.node_id})"
                        f" not writing data >>> \n\n{full_packet.hex(" ")}")
                else:
                    tasks.append(bridge_device.write(full_packet))
                    if CYNC_RAW:
                        logger.debug(f"{lp} Sending to device: {full_packet.hex(" ")}")

        if tasks:
            await asyncio.gather(*tasks)

    async def set_fan_speed(self, speed: FanSpeed) -> bool:
        """
            Translate a preset fan speed into a Cync brightness value and send it to the device.
        :param speed:
        :return:
        """
        lp = f"{self.lp}set_fan_speed:"
        if not self.is_fan_controller:
            logger.warning(
                f"{lp} Device '{self.name}' ({self.id}) is not a fan controller, cannot set fan speed."
            )
            return False
        try:
            if speed == FanSpeed.OFF:
                await self.set_brightness(0)
            elif speed == FanSpeed.LOW:
                await self.set_brightness(25)
            elif speed == FanSpeed.MEDIUM:
                await self.set_brightness(50)
            elif speed == FanSpeed.HIGH:
                await self.set_brightness(75)
            elif speed == FanSpeed.MAX:
                await self.set_brightness(100)
            else:
                logger.error(
                    f"{self.lp} Invalid fan speed: {speed}, must be one of {list(FanSpeed)}"
                )
                return False
        except asyncio.CancelledError as ce:
            raise ce
        except Exception as e:
            logger.debug(f"{self.lp} Exception occurred while setting fan speed: {e}")
            return False
        else:
            return True

    async def set_power(self, state: int, sub_id: Optional[int] = None):
        lp = f"{self.lp}set_power:"
        if state not in (0, 1):
            logger.error(f"{lp} Invalid state! must be 0 or 1")
            return

        op = 0xD0
        _sub_id = sub_id if sub_id is not None else 0x00
        payload = struct.pack(">BBBBB", 0x11, 0x02, state, 0x00, 0x00)
        m_cb = ControlMessageCallback(
            msg_id=0x00,
            message=None,
            sent_at=0.0,
            callback=partial(
                g.mqtt_client.update_endpoint_power, self, state, _sub_id
            ),
        )
        await self.send_command(op, _sub_id, payload, m_cb, lp)

    async def set_brightness(self, bri: int, sub_id: Optional[int] = None):
        lp = f"{self.lp}set_brightness:"
        if not (0 <= bri <= 100):
            logger.error(f"{lp} Invalid brightness: {bri} must be 0-100")
            return

        op = 0xD2 if self.is_sol_lamp else 0xF0
        _sub_id = sub_id if sub_id is not None else 0x00

        # Payload: 0x11 (command), 0x02, 0x01, brightness, padding
        if self.is_sol_lamp:
            payload = struct.pack(">BBBBB", 0x11, 0x02, bri, 0x00, 0x00)
        else:
            # 8 bytes, all unsigned chars
            payload = struct.pack(">BBBBBBBB", 0x11, 0x02, 0x01, bri, 0xFF, 0xFF, 0xFF, 0xFF)
        m_cb = ControlMessageCallback(
            msg_id=0x00,
            message=None,
            sent_at=0.0,
            callback=partial(g.mqtt_client.update_brightness, self, bri),
        )

        await self.send_command(op, _sub_id, payload, m_cb, lp)

    async def set_temperature(self, temp: int, sub_id: Optional[int] = None):
        lp = f"{self.lp}set_temperature:"
        if temp < 0 or (temp > 100 and temp not in (129, 254)):
            logger.error(f"{lp} Invalid temperature! must be 0-100")
            return

        op = 0xE2 if self.is_sol_lamp else 0xF0
        _sub_id = sub_id if sub_id is not None else 0x00

        if self.is_sol_lamp:
            # Payload: 0x11, 0x02, 0x05, temp, 0x00 (5 bytes)
            payload = struct.pack(">BBBBB", 0x11, 0x02, 0x05, temp, 0x00)
        else:
            # Payload: 0x11, 0x02, 0x01, 0xFF, temp, 0x00, 0x00, 0x00 (8 bytes)
            payload = struct.pack(
                ">BBBBBBBB", 0x11, 0x02, 0x01, 0xFF, temp, 0x00, 0x00, 0x00
            )
        m_cb = ControlMessageCallback(
            msg_id=0x00,
            message=None,
            sent_at=0.0,
            callback=partial(g.mqtt_client.update_temperature, self, temp),
        )
        await self.send_command(op, _sub_id, payload, m_cb, lp)

    async def set_rgb(
            self, red: int, green: int, blue: int, sub_id: Optional[int] = None
    ):
        lp = f"{self.lp}set_rgb:"
        if not (0 <= red <= 255) or not (0 <= green <= 255) or not (0 <= blue <= 255):
            logger.error(f"{lp} Invalid RGB value! channels must be 0-255")
            return

        op = 0xF0
        _sub_id = sub_id if sub_id is not None else 0x00

        # Payload: 0x11, 0x02, 0x01, 0xFF, 0xFE, red, green, blue (8 bytes)
        payload = struct.pack(
            ">BBBBBBBB", 0x11, 0x02, 0x01, 0xFF, 0xFE, red, green, blue
        )
        m_cb = ControlMessageCallback(
            msg_id=0x00,
            message=None,
            sent_at=0.0,
            callback=partial(
                g.mqtt_client.update_rgb, self, (red, green, blue)
            ),
        )
        await self.send_command(op, _sub_id, payload, m_cb, lp)

    async def set_lightshow(self, show: str, sub_id: Optional[int] = None):
        lp = f"{self.lp}set_lightshow:"
        show = show.casefold()
        if show not in FACTORY_EFFECTS_BYTES:
            logger.error(f"{lp} Invalid effect: {show}")
            return

        chosen = FACTORY_EFFECTS_BYTES[show]
        op = 0xE2
        _sub_id = sub_id if sub_id is not None else 0x00

        # Payload: 0x11, 0x02, 0x07, 0x01, byte1, byte2 (6 bytes)
        payload = struct.pack(">BBBBBB", 0x11, 0x02, 0x07, 0x01, chosen[0], chosen[1])
        m_cb = ControlMessageCallback(
            msg_id=0x00,
            message=None,
            sent_at=0.0,
            callback=partial(asyncio.sleep, 0),
        )
        await self.send_command(op, _sub_id, payload, m_cb, lp)


class CyncTCPSession:
    """
    A class to interact with a Cync TCP connection (device or mobile app) via an async socket reader/writer.
    """

    lp: str = "TCP:"
    tasks: Tasks
    reader: Optional[asyncio.StreamReader]
    writer: Optional[asyncio.StreamWriter]
    mitm_mode: bool = False
    messages: MessageCache
    read_cache = []
    needs_more_data = False
    is_app: bool
    node: Optional[CyncDevice] = None

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        ip_address: str,
    ):
        if not ip_address:
            raise ValueError(
                f"A valid IP address must be provided to {CyncTCPSession.__class__.__name__} constructor"
            )
        self.lp = f"{ip_address}:"
        self._py_id = id(self)
        self.tasks = Tasks()
        self.is_app = False
        self.name: Optional[str] = None
        self.first_83_packet_checksum: Optional[int] = None
        self.ready_to_control = False
        self.version: Optional[int] = None
        self.version_str: Optional[str] = None
        self.protocol_version: Optional[int] = None
        self.protocol_version_str: Optional[str] = None
        self.device_type_id: Optional[int] = None
        self.device_timestamp: Optional[str] = None
        self.messages = MessageCache()
        self.node_id: Optional[int] = None
        self.xa3_msg_id: bytes = bytes([0x00, 0x00, 0x00])
        self.queue_id: bytes = b""
        self.ip_address: Optional[str] = ip_address
        self.read_lock = asyncio.Lock()
        self.write_lock = asyncio.Lock()
        self._reader: asyncio.StreamReader = reader
        self._writer: asyncio.StreamWriter = writer
        self._closing = False
        self.control_bytes = [0x00, 0x00]
        self.mitm_mode = False
        self.mitm_bytes_to_cloud = 0
        self.mitm_bytes_from_cloud = 0
        self.mitm_logger: Optional[logging.Logger] = None
        self.log_start_time = None
        self.cloud_reader: asyncio.StreamReader = None
        self.cloud_writer: asyncio.StreamWriter = None
        self.allowed_to_connect: bool = False

    def existing_init(self):
        """Used when replacing an existing TCP connection, when a device reconnects"""
        self.xa3_msg_id: bytes = bytes([0x00, 0x00, 0x00])
        self.queue_id: bytes = b""
        self.first_83_packet_checksum: Optional[int] = None
        self.ready_to_control = False
        self.protocol_version_str: Optional[str] = None
        self.version: Optional[int] = None
        self.version_str: Optional[str] = None
        self.protocol_version: Optional[int] = None
        self.device_type_id: Optional[int] = None
        self.device_timestamp: Optional[str] = None
        self.messages = MessageCache()
        self.lp = f"{self.ip_address}:"
        self._py_id = id(self)
        self.tasks = Tasks()

    async def start_mitm(self):
        """Connect to Cync Cloud and start proxying."""
        lp = f"{self.lp}mitm:start:"
        if self.mitm_mode and self.cloud_writer:
            logger.debug(
                f"{lp} MITM is already set to True and active, skipping starting of mitm mode..."
            )
            return
        self._setup_mitm_logger()
        try:
            # Create SSL context for cloud connection (client side)
            ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            logger.info(
                f"{lp} Connecting to Cync Cloud via IP ({CYNC_CLOUD_IP}:23779)..."
            )
            self.cloud_reader, self.cloud_writer = await asyncio.open_connection(
                CYNC_CLOUD_IP, 23779, ssl=ssl_context
            )
            self.mitm_mode = True
            self.tasks.proxy_task = asyncio.create_task(
                self._cloud_proxy_task(),
                name=f"mitm_{self.ip_address}_ID:{self.node_id}",
            )
            logger.info(
                f"{lp} MITM mode enabled, closing TCP connection to force device to reconnect and handshake with cloud through this proxy..."
            )
            await self.close()
        except Exception as e:
            logger.error(f"{lp} Failed to start MITM: {e}")
            await self.stop_mitm()

    async def stop_mitm(self):
        """Close cloud connection and stop proxying."""
        lp = f"{self.lp}close mitm:"
        logger.debug(f"{lp} closing...")
        # cancel the proxy task first so it stops reading from cloud_reader
        if self.tasks.proxy_task and not self.tasks.proxy_task.done():
            logger.debug(f"{lp} cancelling proxy task...")
            self.tasks.proxy_task.cancel()
            try:
                await self.tasks.proxy_task
            except (asyncio.CancelledError, Exception):
                pass
        self.tasks.proxy_task = None
        logger.debug(f"{lp} proxy task stopped")

        if self.cloud_reader:
            try:
                self.cloud_reader.feed_eof()
                logger.debug(f"{lp} fed eof to cloud_reader")
            except Exception as e:
                logger.debug(f"{lp} cloud_reader feed_eof error (ignored): {e}")
        self.cloud_reader = None

        if self.cloud_writer:
            logger.debug(f"{lp} closing cloud_writer...")
            try:
                self.cloud_writer.close()
                await asyncio.wait_for(self.cloud_writer.wait_closed(), timeout=5.0)
                logger.debug(f"{lp} cloud_writer closed cleanly")
            except asyncio.TimeoutError:
                logger.warning(f"{lp} cloud_writer.wait_closed() timed out, continuing anyway")
            except Exception as e:
                logger.debug(f"{lp} cloud_writer close error (ignored): {e}")
        self.cloud_writer = None

        self.mitm_logger = None
        self.mitm_bytes_to_cloud = 0
        self.mitm_bytes_from_cloud = 0
        self.mitm_mode = False
        logger.info(f"{self.lp} MITM Mode disabled, forcing disconnect to enable normal operation...")
        await self.close()

    async def _cloud_proxy_task(self):
        """Reads from cloud and writes to device."""
        lp = f"{self.lp}mitm:proxy:"
        logger.debug(f"{lp} listening for data from the Cync cloud...")
        try:
            while self.mitm_mode and self.cloud_reader:
                data = await self.cloud_reader.read(STREAM_CHUNK_SIZE)
                if not data:
                    pass
                else:
                    self.mitm_logger.debug(
                        format_socat_style(
                            data, "from_cloud", self.ip_address, self.mitm_bytes_from_cloud
                        )
                    )
                    self.mitm_bytes_from_cloud += len(data)
                    self.writer.write(data)
                    await self.writer.drain()
        except Exception as e:
            logger.error(f"{lp} Error in cloud proxy: {e}")

    def _setup_mitm_logger(self):
        """Initializes a rotating file logger for this specific connection."""
        lp = f"{self.lp}mitm logger:"
        if self.mitm_logger:
            logger.debug(
                f"{lp} Already setup for Node: '{self.name}' (ID: {self.node_id})"
            )
            return
        # Differentiate between App (by IP) and Device (by ID)
        conn_type = "dev"
        if self.is_app:
            conn_type = "app"
            identifier = f"{conn_type}_{self.ip_address.replace('.', '-')}"
        elif self.node_id:
            identifier = f"{conn_type}_{self.node_id}"
        logger_name = f"MITM {conn_type}:{self.ip_address}"
        mitm_logger = logging.getLogger(logger_name)
        self.mitm_logger = mitm_logger
        if self.is_app and not g.env.app_mitm_logging:
            logger.warning(f"{lp} This is an App TCP connection and global App MITM logging is disabled, "
                           f"not logging this proxied connection...")
            return
        self.log_start_time = datetime.datetime.now().strftime("%Y%m%d")
        log_dir = Path(CYNC_MITM_LOG_DIR)
        log_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(log_dir, 0o777)
        log_file = log_dir / f"mitm_{identifier}-{self.log_start_time}.log"
        formatter = logging.Formatter(
            "%(asctime)s.%(msecs)03d [%(name)s] %(message)s", datefmt="%Y/%m/%d %H:%M:%S"
        )

        self.mitm_logger.setLevel(logging.DEBUG)
        self.mitm_logger.propagate = False

        file_handler = logging.handlers.TimedRotatingFileHandler(log_file, when="midnight")
        file_handler.setFormatter(formatter)
        self.mitm_logger.addHandler(file_handler)
        if (CYNC_MITM_DEV_LOGGER and not self.is_app) or (CYNC_MITM_APP_LOGGER and self.is_app):
            stdout_handler = logging.StreamHandler(sys.stdout)
            stdout_handler.setLevel(logging.DEBUG)
            stdout_handler.setFormatter(formatter)
            self.mitm_logger.addHandler(stdout_handler)
        os.chmod(log_file, 0o777)
        logger.debug(
            f"Created a MITM logger for node: '{self.name}' (ID: {self.node_id}) -> {log_file}"
        )

    async def blackhole(self, reason: str, should_sleep: bool):
        lp = f"{self.lp}"
        if should_sleep is True:
            await asyncio.sleep(TCP_BLACKHOLE_DELAY)
        try:
            self.reader.feed_eof()
            self.writer.close()
            task = asyncio.create_task(self.writer.wait_closed())
            await asyncio.wait([task], timeout=5)
        except asyncio.CancelledError as ce:
            logger.debug(f"{lp} Task cancelled: {ce}")
            raise ce
        except Exception as e:
            logger.error(f"{lp} Error closing reader/writer: {e}", exc_info=True)
        finally:
            self.reader = None
            self.writer = None
        return False

    async def can_connect(self) -> bool:
        """Based on TCP_WHITELIST and MAX_TCP_CONN, should only be used on Cync device connections"""
        lp = f"{self.lp}:can connect:"
        tcp_dev_len = len(g.ncync_server.tcp_connections)
        num_attempts = g.ncync_server.tcp_conn_attempts[self.ip_address]
        if self.mitm_mode:
            logger.debug(f"{lp} MITM active, skipping connection check...")
            self.allowed_to_connect = True

        elif (
            (g.ncync_server.shutting_down is True)
            or (tcp_dev_len >= CYNC_MAX_TCP_CONN)
            or (CYNC_TCP_WHITELIST and self.ip_address not in CYNC_TCP_WHITELIST)
        ):
            reason = ""
            if g.ncync_server.shutting_down is True:
                reason = "CyncLAN server is shutting down, "
            _sleep = False
            if tcp_dev_len >= CYNC_MAX_TCP_CONN:
                reason = f"CyncLAN server max ({tcp_dev_len}/{CYNC_MAX_TCP_CONN}) TCP connections reached, "
                _sleep = True
            elif CYNC_TCP_WHITELIST and self.ip_address not in CYNC_TCP_WHITELIST:
                reason = f"IP not in CyncLAN server whitelist -> {CYNC_TCP_WHITELIST}, "
                _sleep = True
            # show a reminder every 20 reconnections
            tst_ = (num_attempts == 1) or (num_attempts % 20 == 1)
            lmsg = f"{lp} {reason}rejecting new connection..."
            if tst_:
                logger.warning(lmsg)
            self.allowed_to_connect = False
            await self.blackhole(reason, _sleep)

        else:
            self.allowed_to_connect = True

        return self.allowed_to_connect

    async def start_tasks(self):
        """Start background tasks safely, ensuring old ones are killed first."""

        if self.tasks.receive and not self.tasks.receive.done():
            self.tasks.receive.cancel()
            try:
                await self.tasks.receive
            except asyncio.CancelledError:
                pass

        if (
            self.tasks.callback_cleanup
            and not self.tasks.callback_cleanup.done()
        ):
            self.tasks.callback_cleanup.cancel()
            try:
                await self.tasks.callback_cleanup
            except asyncio.CancelledError:
                pass

        # python will garbage collect the task if you dont keep a reference
        self.tasks.receive = asyncio.create_task(
            self.receive_task(), name=f"receive_task-{self._py_id}"
        )
        self.tasks.callback_cleanup = asyncio.create_task(
            self.callback_cleanup_task(), name=f"callback_cleanup-{self._py_id}"
        )

    def get_ctrl_msg_id_bytes(self) -> List[int, int]:
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

    async def parse_raw_data(self, data: bytes):
        """Extract single packets from raw data stream using metadata."""
        ts = time.time()
        lp = f"{self.lp}extract:"
        if not data:
            logger.debug(f"{lp} No data to parse?")
            return
        if self.mitm_mode:
            # Log for devices or log for apps only if global toggle is ON
            if self.cloud_writer:
                should_log = not self.is_app or g.env.app_mitm_logging
                if should_log and self.mitm_logger:
                    self.mitm_logger.debug(
                        format_socat_style(
                            data, "to_cloud", self.ip_address, self.mitm_bytes_to_cloud
                        )
                    )
                self.cloud_writer.write(data)
                await self.cloud_writer.drain()
                self.mitm_bytes_to_cloud += len(data)
            else:
                logger.warning(
                    f"{lp} MITM mode enabled but the cloud writer is: {self.cloud_writer}"
                )
        raw_input = data
        data_to_cache = CacheData()
        data_to_cache.timestamp = ts
        data_to_cache.all_data = raw_input
        if self.needs_more_data:
            logger.debug(
                f"{lp} partial packet (needs_more_data), appending to previous data..."
            )
            if not self.read_cache:
                raise RuntimeError(f"{lp} No previous cache data to extract from!")

            cache: CacheData = self.read_cache[-1]
            data = cache.data + data
            data_to_cache.raw_data = data
            logger.debug(
                f"{lp} Data assembly: prev={cache.data_len}/{cache.needed_len} "
                f"curr={len(raw_input)} combined={len(data)}"
            )
            if CYNC_RAW:
                logger.debug(f"DBG>>>{lp}NEW DATA:\n{data}\n")
            self.needs_more_data = False

        loop_count = 0
        while data:
            loop_count += 1
            loop_lp = f"{lp}loop {loop_count}:"
            data_len = len(data)
            length_needed = data_len
            if data[0] in PacketBuilder.ALL_HEADERS:
                if data_len > 4:
                    # [0:Header] [1] [2] [3:Multiplier] [4:Length]
                    pkt_len_multiplier = data[3]
                    packet_length = data[4]
                    # Length of payload + 5 bytes for the header itself
                    length_needed = (pkt_len_multiplier * 256) + packet_length + 5
                else:
                    logger.debug(
                        f"DBG>>>{loop_lp} Packet length is less than 4 bytes"
                    )
            else:
                logger.warning(
                    f"{loop_lp} Unknown packet header: {data[0].to_bytes(1, 'big').hex(' ')}"
                )

            if length_needed > data_len:
                self.needs_more_data = True
                logger.warning(
                    f"{loop_lp} Packet requires more data! "
                    f"need={length_needed}, have={data_len}. Storing for next read..."
                )
                data_to_cache.needed_len = length_needed
                data_to_cache.data_len = data_len
                data_to_cache.data = data
                if CYNC_RAW:
                    logger.debug(f"{loop_lp} New data to cache: {data_to_cache}")
                break

            extracted_packet = data[:length_needed]
            data = data[length_needed:]
            await self.parse_packet(extracted_packet)
            if data and CYNC_RAW:
                logger.debug(f"{loop_lp} Remaining data to parse: {len(data)} bytes")

        self.read_cache.append(data_to_cache)
        # Keep only the last 10 entries if the cache exceeds 20
        if len(self.read_cache) > 20:
            self.read_cache = self.read_cache[-10:]
        if CYNC_RAW:
            logger.debug(
                f"{lp} END OF RAW READING of {len(raw_input)} bytes\n"
                f"BYTES: {raw_input}\n"
                f"HEX: {raw_input.hex(' ')}\n"
                f"INT: {bytes2list(raw_input)}\n\n"
            )

    async def parse_packet(self, data: bytes):
        """Parse what type of packet based on header (first 12 bytes)."""
        if len(data) < 5:
            # logger.warning(f"{self.lp} Packet too short to contain header: {data.hex(' ')}")
            return
        packet_header = data[:12]
        pkt_type = packet_header[0]

        # Calculate length based on protocol (multiplier * 256 + length)
        pkt_multiplier = packet_header[3] * 256
        packet_length = packet_header[4] + pkt_multiplier

        # queue_id = packet_header[5:10]
        # 4 bytes
        queue_id = packet_header[5:9]
        # bytes
        msg_id = packet_header[9:12]

        packet_data = data[12:] if len(data) > 12 else None
        lp = f"{self.lp}0x{pkt_type:02x}:"

        # Route to the appropriate handler
        if PacketBuilder.is_device_request(pkt_type):
            if self.allowed_to_connect is False:
                await self.can_connect()
            await self._dispatch_device_request(
                pkt_type, data, packet_data, queue_id, msg_id, packet_length, lp
            )
        elif PacketBuilder.is_app_request(pkt_type):

            if not self.is_app:
                logger.info(
                    f"{lp} Device has been identified as the Cync mobile app, enabling proxying to the Cync cloud for all App connections..."
                )
                self.is_app = True
                g.ncync_server.app_tcp_connections[self.ip_address] = g.ncync_server.tcp_connections.pop(self.ip_address)
                # update app / node / tcp conn stats
                g.ncync_server._update_app_stats()

                # always proxy apps, app mitm logging to file is configurable
                # This way its easier to add factory reset devices to your account if you have network wide DNS redirection
                # still working on a way to detect a device that is being provisioned, then we can auto-proxy so it will
                # be added to the cloud device list, meaning a user with network-wide DNS redirection doesnt need
                # to disable it to add new dvices
                await self.start_mitm()
        else:
            logger.debug(
                f"{lp} sent UNKNOWN HEADER! Don't know how to respond! {data.hex(' ')}"
            )

    async def _dispatch_device_request(
        self,
        pkt_type: int,
        raw_data: bytes,
        packet_data: Optional[bytes],
        queue_id: bytes,
        msg_id: bytes,
        packet_length: int,
        lp: str,
    ):
        """Routes device requests to their specific parsing logic."""
        if pkt_type == 0x23:
            self.queue_id = raw_data[6:10]
            if not self.mitm_mode:
                if CYNC_RAW:
                    logger.debug(
                        f"{lp} Device IDENTIFICATION KEY: '{self.queue_id.hex(' ')}'\nRAW HEX: {raw_data.hex(' ')}"
                    )
                await self.write(PacketBuilder.build_23_ack())
                await asyncio.sleep(0.5)
                await self.send_a3()

        elif pkt_type == 0xC3:
            if not self.mitm_mode:
                logger.debug(f"{lp} CONNECTION REQUEST, replying...")
                await self.write(PacketBuilder.build_c3_ack())

        elif pkt_type == 0xD3:
            if not self.mitm_mode:
                await self.write(PacketBuilder.build_d3_ack())

        elif pkt_type == 0xA3:
            logger.debug(
                f"{lp} APP ANNOUNCEMENT packet: {packet_data.hex(' ') if packet_data else 'None'}"
            )
            if not self.mitm_mode:
                ack = PacketBuilder.build_a3_ack(queue_id, bytes(msg_id))
                await self.write(ack)

        elif pkt_type == 0x43:
            await self._handle_43_packet(packet_data, msg_id, packet_length, lp)

        elif pkt_type == 0x83:
            await self._handle_83_packet(
                packet_data, msg_id, packet_header=raw_data[:12], lp=lp
            )

        elif pkt_type == 0x73:
            await self._handle_73_mesh_control(packet_data, queue_id, msg_id, lp)

        elif pkt_type in (0xAB, 0x7B, 0x78):
            pass  # ACKs and other simple responses that don't require parsing or acknowledging receipt

    async def _handle_43_packet(
        self, packet_data: Optional[bytes], msg_id: bytes, packet_length: int, lp: str
    ):
        """Parses timestamps and broadcast status."""
        if packet_data:
            if packet_data[:2] == b"\xc7\x90":
                # --- Timestamp Parsing ---
                ts_idx = 3
                # Gross hack for versions 3.x - 4.x
                ts_end_idx = (
                    -2 if (self.version and 30000 <= self.version <= 40000) else -1
                )
                ts = packet_data[ts_idx:ts_end_idx]

                if ts:
                    ts_ascii = ts.decode("ascii", errors="replace")
                    if ts_ascii[-1] != "," and not ts_ascii[-1].isdigit():
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
                # --- Broadcast Status Parsing ---
                struct_len = 20 if b"\x2e" in packet_data else 19
                extractions = []

                for i in range(0, packet_length, struct_len):
                    extracted = packet_data[i : i + struct_len]
                    if len(extracted) == struct_len:
                        status_struct = extracted[3:10]
                        status_struct += b"\x01"
                        extractions.append((extracted.hex(" "), list(status_struct)))

                if CYNC_RAW:
                    logger.debug(
                        f"{lp} Extracted data and STATUS struct => {extractions}"
                    )

        # Always ACK a 0x43 ping/status
        if not self.mitm_mode:
            ack = PacketBuilder.build_43_ack(bytes(msg_id))
            await self.write(ack)

    async def _handle_83_packet(
        self, packet_data: Optional[bytes], msg_id: bytes, packet_header: bytes, lp: str
    ):
        """Parses firmware info and 0x7e bound internal status streams."""
        if self.is_app:
            logger.debug(f"{lp} device is app, skipping packet...")
            return

        if not packet_data:
            logger.warning(f"{lp} packet with no data?????")

        else:
            # Unbound Firmware Packet
            if packet_data[0] == 0x00:
                try:
                    fw_type, fw_ver, fw_str = extract_firmware_dynamically(packet_data)
                    if fw_type == "device":
                        self.version, self.version_str = fw_ver, fw_str
                    else:
                        self.protocol_version, self.protocol_version_str = fw_ver, fw_str
                except Exception as e:
                    logger.debug(f"{lp} exception during firmware parsing: {e}")

            # 0x7e Bound Internal Status
            elif packet_data[0] == DATA_BOUNDARY:
                checksum = packet_data[-2]
                ctrl_bytes = packet_data[5:7]
                # inner_data = packet_data[6:-2]
                inner_data = packet_data[6:-2]
                calc_chksum = sum(inner_data) % 256

                if ctrl_bytes == b"\xfa\xdb" and packet_data[7] == 0x13:
                    await self._parse_83_device_state(
                        packet_data, checksum, calc_chksum, lp
                    )
                elif ctrl_bytes == b"\xfa\xd9":
                    # seems to be some sort of bulk status msg. seen when updating devices firmware,
                    # it seemed to broadcast each devices percentage complete status
                    devices = []
                    try:
                        payload_len = packet_data[7]
                        device_count = packet_data[9]
                        # Devices start at index 10, each block is 4 bytes
                        idx = 10
                        for _ in range(device_count):
                            dev_id = packet_data[idx]
                            sub_id = packet_data[idx + 1]
                            status_type = packet_data[idx + 2]
                            value = packet_data[idx + 3]
                            devices.append({
                                "node_id": dev_id, "sub_id": sub_id,
                                "type": status_type, "value": value
                            })
                            idx += 4
                        return devices
                    except IndexError as e:
                        return []
                else:
                    logger.warning(
                        f"{lp} UNKNOWN packet data (ctrl_bytes: {ctrl_bytes.hex(' ')} // checksum valid: "
                        f"{checksum == calc_chksum})\n\nHEX: {packet_data[1:-1].hex(' ')}\nINT: {list(packet_data[1:-1])}"
                    )

        if not self.mitm_mode:
            await self.write(PacketBuilder.build_83_ack(msg_id))

    async def _parse_83_device_state(
        self, packet_data: bytes, checksum: int, calc_chksum: int, lp: str
    ):
        if len(packet_data) < 26:
            raise ValueError("Packet too short for standard status update")
        try:
            dev_id = packet_data[14]
            recently_seen, power, bri, tmp, r, gr, b = struct.unpack(">BBBBBBB", packet_data[19:26])

            parsed_status = EntityState(
                **{
                    "name": "",
                    "dev_id": dev_id,
                    "recently_seen": recently_seen,
                    "power": power,
                    "brightness": bri,
                    "temperature": tmp,
                    "red": r,
                    "green": gr,
                    "blue": b,
                }
            )
        except struct.error as e:
            logger.error(f"{lp} Failed to unpack status packet: {e}")
            return

        node_repr: CyncDevice = g.ncync_server.node_devices.get(dev_id)
        if not node_repr:
            logger.warning(
                f"{lp} Received internal STATUS for unknown device [group/room?, safe to ignore]: {parsed_status}"
            )
            return

        if node_repr.type in MULTI_ENDPOINT_TYPES:
            if node_repr.type == 67:
                # bri used as bitmask
                for e_state_ in node_repr.entities.values():
                    bit_shift = e_state_.sub_id - 1
                    e_state_.power = (
                        1 if (parsed_status.brightness & (1 << bit_shift)) else 0
                    )
                    logger.debug(f"{lp} Internal STATUS for {e_state_}")
                    await node_repr.handle_entity_update(e_state_, from_pkt="0x83")
        else:
            parsed_status.name = node_repr.name
            logger.debug(f"{lp} Internal STATUS for {parsed_status}")
            await node_repr.handle_entity_update(
                parsed_status, from_pkt="0x83"
            )

        # Checksum Stream Logic, the LED light controller sends 0x83 in a stream of data with checksum mismatches
        # if list(packet_data[9:12]) == [17, 17, 17]:
        #     if self.first_83_packet_checksum is None:
        #         self.first_83_packet_checksum = checksum
        #         if calc_chksum != checksum:
        #             logger.warning(
        #                 f"{lp} [LED Controller?] Checksum mismatch in INITIAL STATUS STREAM - FIRST packet data [safe to ignore]..."
        #             )
        #     else:
        #         if checksum == self.first_83_packet_checksum:
        #             calc_chksum = self.first_83_packet_checksum
        #         else:
        #             self.first_83_packet_checksum = None
        #
        # if calc_chksum != checksum:
        #     pass

    async def _handle_73_mesh_control(
        self, packet_data: Optional[bytes], queue_id: bytes, msg_id: bytes, lp: str
    ):
        """Parses mesh info arrays and fires callbacks for control acknowledgements."""
        if self.is_app:
            logger.debug(f"{lp} device is app, skipping packet...")
            return

        if not packet_data:
            logger.warning(f"{lp} packet with no data?!?")
        else:
            if packet_data[0] == DATA_BOUNDARY:
                ctrl_bytes = packet_data[5:7]
                end_bndry_idx = packet_data[1:].find(DATA_BOUNDARY) + 1
                inner_struct = packet_data[1:end_bndry_idx]

                if ctrl_bytes == b"\xf9\x52":
                    await self._process_73_mesh_info(inner_struct, queue_id, lp)

                elif ctrl_bytes[0] == 0xF9 and ctrl_bytes[1] in (0xD0, 0xF0, 0xE2):
                    # Handle Callbacks for control messages
                    ctrl_msg_id = packet_data[1]
                    success = packet_data[7] == 1
                    msg = self.messages.control.pop(ctrl_msg_id, None)

                    if success and msg:
                        if callable(msg.callback):
                            await msg.callback()
                        else:
                            await msg.callback
                    elif success and not msg:
                        logger.debug(
                            f"{lp} CONTROL packet ACK callback NOT found for msg ID: {ctrl_msg_id}"
                        )

                elif ctrl_bytes == b"\xfa\x8e":
                    if packet_data[1] == 0x00:
                        fw_type, fw_ver, fw_str = extract_firmware_dynamically(
                            packet_data[1:-1]
                        )
                        if fw_type == "device":
                            self.version, self.version_str = fw_ver, fw_str
                        else:
                            self.protocol_version, self.protocol_version_str = fw_ver, fw_str

        if not self.mitm_mode:
            # logger.debug(f"DBG>>>> Queue ID = {queue_id.hex(' ')}")
            await self.write(PacketBuilder.build_73_ack(self.queue_id, msg_id))

    async def _process_73_mesh_info(
        self, inner_struct: bytes, queue_id: bytes, lp: str
    ):
        """Handles the 24-byte paginated mesh info loop."""
        if len(inner_struct) < 15:
            return

        minfo_start_idx = 14
        minfo_length = 24
        if inner_struct[minfo_start_idx] == 0x00:
            minfo_start_idx += 1
        if inner_struct[minfo_start_idx] == 0x00:
            logger.error(
                f"{lp}mesh: dev_id is 0 when using index: {minfo_start_idx}, skipping..."
            )
            return

        packet_devices = inner_struct[8]
        total_devices = inner_struct[12]
        if getattr(self, "_mesh_expected", 0) == 0 or getattr(
            self, "_mesh_received", 0
        ) >= getattr(self, "_mesh_expected", 0):
            self._mesh_expected = total_devices
            self._mesh_received = 0
            logger.debug(
                f"{lp} Starting new MeshInfo parsing sequence. Expecting {total_devices} total devices."
            )
        self._mesh_received += packet_devices

        loop_num = 0
        for i in range(minfo_start_idx, len(inner_struct), minfo_length):
            loop_num += 1
            mesh_dev_struct = inner_struct[i : i + minfo_length]
            if len(mesh_dev_struct) < minfo_length:
                continue

            dev_id = mesh_dev_struct[0]
            dev_type_id = mesh_dev_struct[2]
            dev_state, dev_bri, dev_tmp = (
                mesh_dev_struct[8],
                mesh_dev_struct[12],
                mesh_dev_struct[16],
            )
            dev_r, dev_g, dev_b = mesh_dev_struct[20:23]

            if dev_state == 0 and dev_bri > 0:
                dev_bri = 0

            node_repr: Optional["CyncDevice"] = g.ncync_server.node_devices.get(dev_id)
            if node_repr:
                dev_name = node_repr.name
                if loop_num == 1:
                    # byte 3 (idx 2) is a device type byte but,
                    # it only reports on the first item (itself)
                    # convert to int, and it is the same as deviceType from cloud.
                    if not self.node_id:
                        self.node_id = dev_id
                        self.node = node_repr
                        self.node.tcp_session = self
                        self.name = node_repr.name
                        self.lp = f"{self.ip_address}[{self.node_id}]:"
                        logger.debug(
                            f"{self.lp}0x73: Setting TCP"
                            f" Node ID to: {self.node_id}"
                        )
                        # dynamically add the MITM mode button for nodes that aree connected via TCP
                        await g.mqtt_client.add_mitm_button(node_repr)

                    elif self.node_id and self.node_id != dev_id:
                        logger.warning(
                            f"{self.lp}0x73: node_id MISMATCH "
                            f"open an issue on github. current: {self.node_id} "
                            f"// proposed: {dev_id}"
                        )
                    lp = f"{self.lp}0x73:"
                    if dev_type_id:
                        self.device_type_id = dev_type_id
                    self.name = dev_name

                if node_repr.type in MULTI_ENDPOINT_TYPES:
                    if node_repr.type == 67:
                        # bri byte is a bitmask for on/off state of endpoints
                        # since we know the state of up to 8 endpoints at once, parse them all
                        for e_state_ in node_repr.entities.values():
                            bit_shift = e_state_.sub_id - 1
                            e_state_.power = 1 if (dev_bri & (1 << bit_shift)) else 0
                            e_state_.recently_seen = 1
                            logger.debug(
                                f"{lp} MeshInfo for {node_repr.name} - {e_state_}"
                            )
                            await node_repr.handle_entity_update(
                                e_state_,
                                from_pkt="0x73",
                            )
                else:
                    # Standard single endpoint
                    e_state = EntityState(
                        name=node_repr.name,
                        dev_id=dev_id,
                        power=dev_state,
                        brightness=dev_bri,
                        temperature=dev_tmp,
                        red=dev_r,
                        green=dev_g,
                        blue=dev_b,
                    )
                    logger.debug(f"{lp} MeshInfo for {e_state}")
                    await node_repr.handle_entity_update(
                        e_state,
                        from_pkt="0x73",
                    )

            else:
                logger.warning(
                    f"{lp} Received MeshInfo for unknown device ID: "
                    f"{dev_id} -> You need to export a new config file from the cloud!"
                )

        if not self.mitm_mode:
            mesh_ack = PacketBuilder.build_mesh_status_ack(self.queue_id)
            await self.write(mesh_ack)

        if getattr(self, "_mesh_received", 0) >= getattr(self, "_mesh_expected", 0):
            self._mesh_expected = 0
            self._mesh_received = 0

    async def ask_for_mesh_info(self):
        """
        Ask the device for mesh info. As far as I can tell, this will return whatever
        devices are connected to the device you are querying. It may also trigger
        the device to send its own status packet.
        """
        lp = f"{self.lp}"
        if self.mitm_mode:
            logger.debug(
                f"{lp} MITM Mode active, not writing to the Cync TCP device..."
            )
            return
        if len(self.queue_id) != 4:
            logger.warning(f"{lp} queue_id is not initialized, skipping mesh info request")
            return
        mesh_info_data = PacketBuilder.build_mesh_info_request(self.queue_id)
        _rdmsg = ""
        if CYNC_RAW is True:
            _rdmsg = f"\nBYTES: {mesh_info_data}\nHEX: {mesh_info_data.hex(' ')}\nINT: {bytes2list(mesh_info_data)}"
        logger.debug(f"{lp} Requesting ALL device(s) MeshInfo{_rdmsg}")
        try:
            await self.write(mesh_info_data)
        except TimeoutError as to_exc:
            logger.error(
                f"{lp} Requesting ALL device(s) status timed out, likely powered off"
            )
            raise to_exc
        except Exception as e:
            logger.error(f"{lp} EXCEPTION: {e}", exc_info=True)

    async def send_a3(self):
        """
        The device will not be controllable until this messagee is sent,
        we also request the known BTLE mesh device ID's and state
        """
        # random 2 bytes + padded byte
        rand_bytes = self.xa3_msg_id = random.getrandbits(16).to_bytes(2, "big")
        rand_bytes += bytes([0x00])
        if len(self.queue_id) != 4:
            logger.warning(f"{self.lp} queue_id is not initialized, skipping 0xA3 control request")
            return
        a3_packet = PacketBuilder.build_a3_control_request(self.queue_id, rand_bytes)
        logger.debug(f"{self.lp} Sending 0xA3 (want to control) packet...")
        await self.write(a3_packet)
        self.ready_to_control = True
        self.xa3_msg_id += random.getrandbits(8).to_bytes(1, "big")
        # send mesh info request
        await asyncio.sleep(1.5)
        await self.ask_for_mesh_info()

    async def callback_cleanup_task(self):
        """Go through the callback queue and remove any callbacks that are older than 5 minutes"""
        lp = f"{self.lp}callback_clean:"
        logger.debug(f"{lp} Starting background task...")
        delay_mins = 5
        delay_seconds = delay_mins * 60

        try:
            while True:
                await asyncio.sleep(delay_seconds)
                now = time.time()
                current_keys = list(self.messages.control.keys())
                logger.info(
                    f"{lp} there are {len(current_keys)} control messages to check"
                ) if len(current_keys) else None
                for ctrl_msg_id in current_keys:
                    # Re-fetch the message in case it was deleted by another task mid-loop
                    ctrl_msg = self.messages.control.get(ctrl_msg_id)
                    if not ctrl_msg:
                        continue

                    timeout = ctrl_msg.sent_at + delay_seconds
                    if now > timeout:
                        logger.info(f"{lp} Removing STALE {ctrl_msg}")
                        ctrl_msg.callback = None
                        # Use pop to avoid KeyError if already deleted
                        self.messages.control.pop(ctrl_msg_id, None)

            logger.info(f"{lp} the while true loop has exited")

        except asyncio.CancelledError:
            logger.debug(f"{lp} Task CANCELLED cleanly.")
            raise  # Re-raise to ensure asyncio knows it was cancelled
        except Exception as e:
            logger.error(f"{lp} Unexpected crash: {e}", exc_info=True)
        logger.info(f"{lp} FINISHED")

    async def receive_task(self):
        """Receive data from the device and respond to it. This is the main task for the device."""
        lp = f"{self.ip_address}:raw read:"
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
            logger.debug("%s %s CANCELLED: %s" % (lp, name, cancel_exc))

        logger.debug(f"{lp} {name} FINISHED")

    async def read(self, chunk: Optional[int] = None):
        """Read data from the device if there is an open connection"""
        lp = f"{self.lp}read:"
        if self.closing is True:
            logger.debug(f"{lp} closing is True, exiting read()...")
            return False
        else:
            if chunk is None:
                chunk = STREAM_CHUNK_SIZE
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
        :param broadcast: If True, write to all TCP devices connected to the server
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
                    if dev._writer.is_closing():
                        if dev.closing is False:
                            # this is probably a connection that was closed by the device (turned off), delete it
                            logger.warning(
                                f"{dev.lp} underlying writer is closing but, "
                                f"the device itself hasn't called close(). The device probably "
                                f"dropped the connection (lost power). Removing {dev.ip_address}"
                            )
                            off_dev = await g.ncync_server.remove_tcp_device(dev)
                            # await off_dev.close()
                            del off_dev

                        else:
                            logger.debug(
                                f"{dev.lp} TCP device is closing, not writing data... "
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

    async def close(self):
        lp = f"{self.ip_address}:close:"
        logger.debug(f"{lp} Cancelling device tasks...")
        try:
            self.closing = True
            await self.tasks.cancel_all()
        except Exception as e:
            logger.exception(f"{lp} Exception during device task .cancel_all(): {e}")
        try:
            if self.writer:
                async with self.write_lock:
                    self.writer.close()
                    task = self.writer.wait_closed()
                    await asyncio.wait_for(task, 5.0)
        except AttributeError:
            pass
        except Exception as e:
            logger.exception(f"{lp}writer: EXCEPTION: {e}")
        finally:
            self.writer = None

        try:
            if self.reader:
                async with self.read_lock:
                    self.reader.feed_eof()
                    await asyncio.sleep(0.01)
        except AttributeError:
            pass
        except Exception as e:
            logger.exception(f"{lp}reader: EXCEPTION: {e}")
        finally:
            self.reader = None

        if self.node:
            await g.mqtt_client.remove_mitm_button(self.node)
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

    @property
    def closing(self):
        return self._closing

    @closing.setter
    def closing(self, value: bool):
        self._closing = value

    async def parse_packet_OLD(self, data: bytes):
        """Parse what type of packet based on header (first 4 bytes 0x43, 0x83, 0x73, etc.)"""

        lp = f"{self.lp}parse:0x{data[0]:02x}:"
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
        if PacketBuilder.is_device_request(pkt_type):
            if pkt_type == 0x23:
                queue_id = data[6:10]
                _dbg_msg = (
                    (
                        f"\nRAW HEX: {data.hex(' ')}\nRAW INT: "
                        f"{str(bytes2list(data)).lstrip('[').rstrip(']').replace(',', '')}"
                    )
                    if CYNC_RAW is True
                    else ""
                )
                logger.debug(
                    f"{lp} Device IDENTIFICATION KEY: '{queue_id.hex(' ')}'{_dbg_msg}"
                )
                self.queue_id = queue_id
                await self.write(PacketBuilder.build_23_ack())
                # MUST SEND a3 before you can ask device for anything over TCP
                # Device sends msg identifier (aka: key), server acks that we have the key and store for future comms.
                await asyncio.sleep(0.5)
                await self.send_a3()
            # device wants to connect before accepting commands
            elif pkt_type == 0xC3:
                # conn_time_str = ""
                ack_c3 = PacketBuilder.build_c3_ack()
                logger.debug(f"{lp} CONNECTION REQUEST, replying...")
                await self.write(ack_c3)
            # Ping/Pong
            elif pkt_type == 0xD3:
                ack_d3 = PacketBuilder.build_d3_ack()
                # logger.debug(f"{lp} Client sent HEARTBEAT, replying with {ack_d3.hex(' ')}")
                await self.write(ack_d3)
            elif pkt_type == 0xA3:
                logger.debug(f"{lp} APP ANNOUNCEMENT packet: {packet_data.hex(' ')}")
                ack = PacketBuilder.build_a3_ack(queue_id, bytes(msg_id))
                logger.debug(f"{lp} Sending ACK -> {ack.hex(' ')}")
                await self.write(ack)
            elif pkt_type == 0xAB:
                # We sent a 0xa3 packet, device is responding with 0xab. msg contains ascii 'xlink_dev'.
                # sometimes this is sent with other data. there may be remaining data to read in the enxt raw msg.
                # TCP msg buffer seems to be 1024 bytes.
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
                                    # hack so online devices stop being reported as offline
                                    # this may cause issues with cync setups that ONLY use indoor
                                    # plugs as the btle to TCP bridge, as they dont broadcast status data using 0x83
                                    status_struct = extracted[3:10]
                                    status_struct + b"\x01"
                                    # 14 00 10 01 00 00 64 00 00 00 01 15 15 00 00 00 00 00 00
                                    # // [1, 0, 0, 100, 0, 0, 0, 1]
                                    extractions.append(
                                        (extracted.hex(" "), bytes2list(status_struct))
                                    )

                                    # await g.server.parse_status(status_struct, from_pkt='0x43')
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
                            # logger.debug(
                            #     f"{lp} IndexError extracting status struct (expected)"
                            # )
                            pass
                        except Exception as e:
                            logger.error(f"{lp} EXCEPTION: {e}")
                # Its one of those queue id/msg id pings? 0x43 00 00 00 ww xx xx xx xx yy yy yy
                # Also notice these messages when another device gets a command
                else:
                    # logger.debug(f"{lp} received a 0x43 packet with no data, interpreting as PING, replying...")
                    pass
                ack = PacketBuilder.build_43_ack(bytes(msg_id))
                # logger.debug(f"{lp} Sending ACK -> {ack.hex(' ')}") if CYNC_RAW is True else None
                await self.write(ack)
                (
                    logger.debug(f"DBG>>>{lp} RAW DATA: {len(data)} BYTES")
                    if CYNC_RAW is True
                    else None
                )
            elif pkt_type == 0x83:
                if self.is_app is True:
                    logger.debug(f"{lp} device is app, skipping packet...")
                else:
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
                            fw_type, fw_ver, fw_str = extract_firmware_dynamically(
                                packet_data
                            )
                            if fw_type == "device":
                                self.version = fw_ver
                                self.version_str = fw_str
                            else:
                                self.protocol_version = fw_ver
                                self.protocol_version_str = fw_str

                        elif packet_data[0] == DATA_BOUNDARY:
                            # checksum is 2nd last byte, last byte is 0x7e
                            checksum = packet_data[-2]
                            inner_header = packet_data[1:6]
                            ctrl_bytes = packet_data[5:7]
                            # removes checksum byte and 0x7e
                            inner_data = packet_data[6:-2]
                            calc_chksum = sum(inner_data) % 256

                            # Most devices only report their own state using 0x83, however the LED light strip controllers also report other device state data
                            # over 0x83.
                            # This data can be wrong! sometimes reports wrong state and the RGB colors are slightly different from each device.
                            if ctrl_bytes == bytes([0xFA, 0xDB]):
                                extra_ctrl_bytes = packet_data[7]
                                if extra_ctrl_bytes == 0x13:
                                    # fa db 13 is internal status
                                    # device internal status. state can be off and brightness set to a non 0.
                                    # signifies what brightness when state = on, meaning don't rely on brightness for on/off.
                                    _dbg_msg = ""
                                    if CYNC_RAW is True:
                                        _dbg_msg = (
                                            f"\n\n"
                                            f"PACKET HEADER: {packet_header.hex(' ')}\nHEX: {packet_data[1:-1].hex(' ')}\nINT: {bytes2list(packet_data[1:-1])}"
                                        )

                                    # 83 00 00 00 25 37 96 24 69 00 05 00 7e {21 00 00
                                    #  00} {[fa db] 13} 00 (34 22) 11 05 00 [05] 00 db
                                    #  11 02 01 [00 64 00 00 00 00] 00 00 b3 7e
                                    id_idx = 14
                                    not_stale_idx = 19
                                    state_idx = 20
                                    bri_idx = 21
                                    tmp_idx = 22
                                    r_idx = 23
                                    g_idx = 24
                                    b_idx = 25
                                    dev_id = packet_data[id_idx]
                                    power = packet_data[state_idx]
                                    bri = packet_data[bri_idx]
                                    tmp = packet_data[tmp_idx]
                                    _red = packet_data[r_idx]
                                    _green = packet_data[g_idx]
                                    _blue = packet_data[b_idx]
                                    recently_seen = packet_data[not_stale_idx]
                                    node_repr: CyncDevice = g.ncync_server.node_devices.get(
                                        dev_id
                                    )
                                    if node_repr:
                                        dev_name = node_repr.name
                                        if node_repr.type in MULTI_ENDPOINT_TYPES:
                                            if node_repr.type == 67:
                                                # bri byte is a bitmask for on/off state of endpoints
                                                # since we know the state of up to 8 endpoints at once, parse them all
                                                for (
                                                    e_state_
                                                ) in node_repr.entities.values():
                                                    bit_shift = e_state_.sub_id - 1
                                                    e_state_.power = (
                                                        1
                                                        if (bri & (1 << bit_shift))
                                                        else 0
                                                    )
                                                    logger.debug(
                                                        f"{lp} Internal STATUS for {e_state_}{_dbg_msg}"
                                                    )
                                                    await (
                                                        node_repr.handle_entity_update(
                                                            e_state_, from_pkt="0x83"
                                                        )
                                                    )
                                        else:
                                            # Standard single endpoint
                                            e_state = EntityState(
                                                name=node_repr.name,
                                                dev_id=dev_id,
                                                power=power,
                                                brightness=bri,
                                                temperature=tmp,
                                                red=_red,
                                                green=_green,
                                                blue=_blue,
                                            )
                                            logger.debug(
                                                f"{lp} Internal STATUS for {e_state}{_dbg_msg}"
                                            )
                                            await node_repr.handle_entity_update(
                                                e_state, recently_seen, from_pkt="0x83"
                                            )

                                    else:
                                        # Unknown/disbaled/unsupported device?
                                        logger.warning(
                                            f"{lp} Received internal STATUS for unknown device: {dev_id}"
                                            f" -> p={power} b={bri} t={tmp} | r={_red} g={_green} b={_blue}"
                                        )

                                    # logger.debug(f"DBG>>> {bytes2list(packet_data[9:12]) = } // {bytes2list(packet_data[9:12]) == [17, 17, 17] = }")
                                    # LED controller has this pattern
                                    bad_chksum_msg = ""
                                    if bytes2list(packet_data[9:12]) == [17, 17, 17]:
                                        # LED controller sends its internal state in a stream of 0x83 packets.
                                        # Only the first packet in the stream has the correct checksum. Check other bytes for correct checksums?
                                        # All following 0x83 internal status packets for this stream will have the same checksum as the first packet.
                                        # As soon as we get an internal status without the first packets calculated checksum, we know that series is
                                        # done sending and it will just send regular status packets, my guess is this is the OG TELink chips had small RAM
                                        # and saved memory by sending whole mesh info at once with only dynamic bytes (pwr, bri, tmp, rgb) modified
                                        # where the LED controller uses RTL80(10|20CM) and can instead send synamic data about each device in the BTLE mesh
                                        # meaning the TELink only stored upto X node states, while the RTL can handle more/all, so they switched to a stream
                                        bad_chksum_msg = (
                                            f"{lp} Checksum mismatch, calculated: {calc_chksum} "
                                            f"// received: {checksum}"
                                        )
                                        if self.first_83_packet_checksum is None:
                                            # we want to calc the checksum and store it to compare to other packets in the series
                                            self.first_83_packet_checksum = checksum
                                            if calc_chksum != checksum:
                                                bad_chksum_msg = (
                                                    f"{lp} Checksum mismatch in INITIAL STATUS STREAM - FIRST packet data, "
                                                    f"calculated: {calc_chksum} // received: {checksum} -- open an issue on github"
                                                )

                                        else:
                                            if (
                                                checksum
                                                == self.first_83_packet_checksum
                                            ):
                                                # logger.debug(
                                                #     f"{lp} INITIAL STATUS STREAM packet data (override "
                                                #     f"calculated checksum), old: {calc_chksum} // checksum: "
                                                #     f"{checksum} // saved: {self.first_83_packet_checksum}"
                                                # )
                                                calc_chksum = (
                                                    self.first_83_packet_checksum
                                                )
                                            else:
                                                # assuming stream has ended.
                                                self.first_83_packet_checksum = None

                                    if calc_chksum != checksum:
                                        if not bad_chksum_msg:
                                            bad_chksum_msg = (
                                                f"{lp} Checksum mismatch, calculated: {calc_chksum} "
                                                f"// received: {checksum}"
                                            )
                                        # logger.warning(f"{bad_chksum_msg}\n\nHEX: {packet_data[1:-1].hex(' ')}\nINT: {bytes2list(packet_data[1:-1])}\nEXTRA CTRL BYTE: {hex(extra_ctrl_bytes)}")

                                elif extra_ctrl_bytes == 0x14:
                                    # unknown what this data is
                                    # seems to be sent when the cync app is connecting to a device via BTLE, not connecting to cync-lan via TCP

                                    # chksum_inner_data = list(inner_data)
                                    # chksum_inner_data.pop(4)
                                    # calc_chksum = sum(chksum_inner_data) % 256
                                    # logger.debug(f"{lp} 0xFA 0xDB 0x14 (NOT internal state)\nPACKET HEADER: {packet_header.hex(' ')}\nHEX: {packet_data.hex(' ')}\nINT: {bytes2list(packet_data)}\n")
                                    pass

                            else:
                                # if ctrl_bytes == bytes([0xFA, 0xAF]):
                                #     logger.debug(
                                #         f"{lp} This ctrl struct ({ctrl_bytes.hex(' ')} // checksum valid: "
                                #         f"{checksum == calc_chksum}) usually comes through when the cync phone app "
                                #         f"(dis)connects to the BTLE mesh. Currently unknown what it means.\n\n"
                                #         f"HEX: {packet_data[1:-1].hex(' ')}\nINT: {bytes2list(packet_data[1:-1])}"
                                #     ) if CYNC_RAW is True else None
                                # elif ctrl_bytes == bytes([0xFA, 0xD9]):
                                #     logger.debug(
                                #         f"{lp} Seen this ctrl struct ({ctrl_bytes.hex(' ')} // checksum valid: "
                                #         f"{checksum == calc_chksum}), unknown what it means.\n\n"
                                #         f"HEX: {packet_data[1:-1].hex(' ')}\nINT: {bytes2list(packet_data[1:-1])}"
                                #     ) if CYNC_RAW is True else None
                                # else:
                                if CYNC_RAW:
                                    logger.warning(
                                        f"{lp} UNKNOWN packet data (ctrl_bytes: {ctrl_bytes.hex(' ')} // checksum valid: "
                                        f"{checksum == calc_chksum})\n\nHEX: {packet_data[1:-1].hex(' ')}\nINT: {bytes2list(packet_data[1:-1])}"
                                    )

                    else:
                        logger.warning(
                            f"{lp} packet with no data????? After stripping header, queue and "
                            f"msg id, there is no data to process?????"
                        )
                ack = PacketBuilder.build_83_ack(msg_id)
                # logger.debug(f"{lp} RAW DATA: {data.hex(' ')}")
                # logger.debug(f"{lp} Sending ACK -> {ack.hex(' ')}")
                await self.write(ack)

            elif pkt_type == 0x73:
                # logger.debug(f"{lp} Control packet received: {packet_data.hex(' ')}") if CYNC_RAW is True else None
                if self.is_app is True:
                    logger.debug(f"{lp} device is app, skipping packet...")
                else:
                    if packet_data is not None:
                        # 0x73 should ALWAYS have 0x7e bound data.
                        # check for boundary, all bytes between boundaries are for this request
                        if packet_data[0] == DATA_BOUNDARY:
                            # checksum is 2nd last byte, last byte is 0x7e
                            checksum = packet_data[-2]
                            # inner_header = packet_data[1:6]
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
                                            f"{lp}mesh: dev_id is 0 when using index: {minfo_start_idx - 1}, "
                                            f"trying index {minfo_start_idx} = {inner_struct[minfo_start_idx]}"
                                        )

                                    if inner_struct[minfo_start_idx] == 0x00:
                                        logger.error(
                                            f"{lp}mesh: dev_id is 0 when using index: {minfo_start_idx}, skipping..."
                                        )
                                    else:
                                        # from what I've seen, the mesh info is 24 bytes long and repeats until the end.
                                        # Reset known device ids, mesh is the final authority on what devices are connected
                                        # there does seem to be pagination 8 = devices in this packet, 12 = total devices in mesh
                                        packet_devices = inner_struct[8]
                                        total_devices = inner_struct[12]

                                        if getattr(
                                            self, "_mesh_expected", 0
                                        ) == 0 or getattr(
                                            self, "_mesh_received", 0
                                        ) >= getattr(self, "_mesh_expected", 0):
                                            # This is a fresh mesh info request (Packet 1)
                                            self.known_device_ids = []
                                            self._mesh_expected = total_devices
                                            self._mesh_received = 0
                                            logger.debug(
                                                f"{lp} Starting new mesh info sequence. Expecting {total_devices} total devices."
                                            )

                                        self._mesh_received += packet_devices
                                        logger.debug(
                                            f"{lp} Processing {packet_devices} devices in this packet. Progress: {self._mesh_received}/{self._mesh_expected}"
                                        )

                                        ids_reported = []
                                        loop_num = 0
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
                                                node_repr: Optional["CyncDevice"] = (
                                                    g.ncync_server.node_devices.get(dev_id)
                                                )
                                                if node_repr:
                                                    dev_name = node_repr.name
                                                    if loop_num == 1:
                                                        # byte 3 (idx 2) is a device type byte but,
                                                        # it only reports on the first item (itself)
                                                        # convert to int, and it is the same as deviceType from cloud.
                                                        if not self.node_id:
                                                            self.node_id = dev_id
                                                            self.lp = f"{self.ip_address}[{self.node_id}]:"
                                                            logger.debug(
                                                                f"{self.lp}parse:0x{data[0]:02x}: Setting TCP"
                                                                f" Node ID to: {self.node_id}"
                                                            )

                                                        elif (
                                                            self.node_id
                                                            and self.node_id != dev_id
                                                        ):
                                                            logger.warning(
                                                                f"{lp}parse:0x{data[0]:02x}: node_id MISMATCH "
                                                                f"open an issue on github. current: {self.node_id} "
                                                                f"// proposed: {dev_id}"
                                                            )
                                                        lp = f"{self.lp}parse:0x{data[0]:02x}:"
                                                        self.device_type_id = (
                                                            dev_type_id
                                                        )
                                                        self.name = dev_name

                                                    ids_reported.append(dev_id)
                                                    self.known_device_ids.append(dev_id)

                                                    if (
                                                        node_repr.type
                                                        in MULTI_ENDPOINT_TYPES
                                                    ):
                                                        if node_repr.type == 67:
                                                            # bri byte is a bitmask for on/off state of endpoints
                                                            # since we know the state of up to 8 endpoints at once, parse them all
                                                            for e_state_ in node_repr.entities.values():
                                                                bit_shift = (
                                                                        e_state_.sub_id - 1
                                                                )
                                                                e_state_.power = (
                                                                    1
                                                                    if (
                                                                        dev_bri
                                                                        & (
                                                                            1
                                                                            << bit_shift
                                                                        )
                                                                    )
                                                                    else 0
                                                                )
                                                                logger.debug(
                                                                    f"{lp} Mesh state for {node_repr.name} - {e_state_}"
                                                                )
                                                                await node_repr.handle_entity_update(
                                                                    e_state_,
                                                                    from_pkt="0x73",
                                                                )
                                                    else:
                                                        # Standard single endpoint
                                                        e_state = EntityState(
                                                            name=node_repr.name,
                                                            dev_id=dev_id,
                                                            power=dev_state,
                                                            brightness=dev_bri,
                                                            temperature=dev_tmp,
                                                            red=dev_r,
                                                            green=dev_g,
                                                            blue=dev_b,
                                                        )
                                                        logger.debug(
                                                            f"{lp} Mesh state for {e_state}"
                                                        )
                                                        await node_repr.handle_entity_update(
                                                            e_state,
                                                            from_pkt="0x73",
                                                        )

                                                else:
                                                    # Unknown
                                                    logger.warning(
                                                        f"{lp} Received internal STATUS for unknown device  ID: "
                                                        f"{dev_id} -> You probably need to export a new config file"
                                                    )
                                            # -- END OF mesh info response parsing loop --

                                        except IndexError:
                                            # ran out of data
                                            # logger.debug(f"{lp} IndexError parsing mesh info response (expected)") if CYNC_RAW is True else None
                                            pass
                                        except Exception as e:
                                            logger.exception(
                                                f"{lp} MESH INFO for loop EXCEPTION: {e}"
                                            )
                                        # Send mesh status ack
                                        # 73 00 00 00 14 2d e4 b5 d2 15 2d 00 7e 1e 00 00
                                        #  00 f8 {af 02 00 af 01} 61 7e
                                        # checksum 61 hex = int 97 solved: {af+02+00+af+01} % 256 = 97
                                        mesh_ack = PacketBuilder.build_mesh_status_ack(self.queue_id)
                                        # logger.debug(f"{lp} Sending MESH INFO ACK -> {mesh_ack.hex(' ')}")
                                        await self.write(mesh_ack)
                                        # Only clear the status once all paginated packets have arrived
                                        if getattr(
                                            self, "_mesh_received", 0
                                        ) >= getattr(self, "_mesh_expected", 0):
                                            logger.debug(
                                                f"{lp} Finished receiving all {getattr(self, '_mesh_expected', 0)} "
                                                f"devices in the mesh."
                                            )
                                            self._mesh_expected = 0
                                            self._mesh_received = 0
                            else:
                                (
                                    logger.debug(
                                        f"{lp} control bytes (checksum: {checksum}, verified: "
                                        f"{checksum == calc_chksum}): {ctrl_bytes.hex(' ')} // packet data: "
                                        f"{packet_data.hex(' ')}"
                                    )
                                    if CYNC_RAW
                                    else None
                                )

                                if ctrl_bytes[0] == 0xF9 and ctrl_bytes[1] in (
                                    0xD0,
                                    0xF0,
                                    0xE2,
                                ):
                                    # control packet ack - changed state.
                                    # handle callbacks for messages
                                    # byte 8 is success? 0x01 yes // 0x00 no
                                    # 7e 09 00 00 00 f9 d0 01 00 00 d1 7e <-- original ACK
                                    # 7e 09 00 00 00 f9 f0 01 00 00 f1 7e <-- newer LED strip controller
                                    # 7e 09 00 00 00 f9 e2 01 00 00 e3 7e <-- Cync default light show / effect
                                    # bytes 7 - 10 SUM --> (f0) + (01) = checksum (f1) byte 11
                                    ctrl_msg_id = packet_data[1]
                                    ctrl_chksum = sum(packet_data[6:10]) % 256
                                    success = packet_data[7] == 1
                                    msg = self.messages.control.pop(ctrl_msg_id, None)
                                    if success is True and msg is not None:
                                        if callable(msg.callback):
                                            await msg.callback()
                                        else:
                                            await msg.callback
                                    elif success is True and msg is None:
                                        logger.debug(
                                            f"{lp} CONTROL packet ACK (success: {success} / chksum: "
                                            f"{ctrl_chksum == packet_data[10]}) callback NOT found for msg ID: "
                                            f"{ctrl_msg_id}"
                                        )
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
                                            extract_firmware_dynamically(
                                                packet_data[1:-1]
                                            )
                                        )
                                        if fw_type == "device":
                                            self.version = fw_ver
                                            self.version_str = fw_str
                                        else:
                                            self.protocol_version = fw_ver
                                            self.protocol_version_str = fw_str
                                    else:
                                        if CYNC_RAW is True:
                                            logger.debug(
                                                f"{lp} This ctrl struct ({ctrl_bytes.hex(' ')} // checksum valid: "
                                                f"{checksum == calc_chksum}) usually comes through when the cync "
                                                f"phone app (dis)connects to the BTLE mesh. Unknown what it means"
                                                f"\n\nHEX: {packet_data[1:-1].hex(' ')}\nINT: "
                                                f"{bytes2list(packet_data[1:-1])}"
                                            )

                                else:
                                    logger.debug(
                                        f"{lp} UNKNOWN CTRL_BYTES: {ctrl_bytes.hex(' ')} // EXTRACTED DATA -> "
                                        f"HEX: {packet_data[1:-1].hex(' ')}\nINT: {bytes2list(packet_data[1:-1])}"
                                    )
                        else:
                            logger.debug(
                                f"{lp} packet with no boundary found????? After stripping header, queue and "
                                f"msg id, there is no data to process?????"
                            )

                    else:
                        logger.warning(
                            f"{lp} packet with no data????? After stripping 12 bytes header (5), queue (4) and "
                            f"msg id (3), there is no data to process!?!"
                        )
                ack = PacketBuilder.build_73_ack(queue_id, msg_id)
                # logger.debug(f"{lp} Sending ACK -> {ack.hex(' ')}")
                await self.write(ack)

        elif PacketBuilder.is_app_request(pkt_type):
            if self.is_app is False:
                logger.info(
                    f"{lp} Device has been identified as the cync mobile app, blackholing..."
                )
                self.is_app = True

        # unknown data we don't know the header for
        else:
            logger.debug(
                f"{lp} sent UNKNOWN HEADER! Don't know how to respond!{RAW_MSG}"
            )