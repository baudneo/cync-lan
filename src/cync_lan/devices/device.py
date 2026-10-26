import asyncio
import logging
import logging.handlers
import random
import struct
import time
from functools import partial
from typing import TYPE_CHECKING, Collection, Dict, List, Optional, Set, Union

from cync_lan.const import (
    CYNC_CMD_BROADCASTS,
    CYNC_LOG_NAME,
    CYNC_RAW,
    FACTORY_EFFECTS_BYTES,
    light_show_id,
)
from cync_lan.metadata.model_info import (
    DeviceClassification,
    DeviceTypeInfo,
    device_type_map,
)
from cync_lan.packet import PacketBuilder
from cync_lan.stats import stats
from cync_lan.structs import (
    ControlMessageCallback,
    EntityState,
    FanSpeed,
    GlobalObject,
)
from cync_lan.utils import bytes2list

if TYPE_CHECKING:
    from cync_lan.devices.session import CyncTCPSession

__all__ = ["CyncDevice"]
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
        self.stale_voters: Set[str] = set()
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
    def has_multi_entities(self) -> bool:
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

    @staticmethod
    def stale_quorum(pool_size: int) -> int:
        """Distinct live TCP bridges that must report a device stale before it is marked offline: a strict majority,
        or the lone bridge if there is only one. Requiring *every* bridge is too strict: each bridge reports only the
        devices it has heard from, so one bridge that never mentions a dead bulb keeps it "on" forever."""
        return 1 if pool_size <= 1 else pool_size // 2 + 1

    def stale_vote_passes(self, live_ips: Collection[str]) -> bool:
        """Votes from bridges that have since disconnected don't count, and neither do their seats in the quorum."""
        live = set(live_ips)
        return len(self.stale_voters & live) >= max(1, self.stale_quorum(len(live)))

    def revote_stale(self, live_ips: Collection[str]) -> bool:
        """Re-run the stale vote after the TCP pool changed. Stale reports are only evaluated when they arrive, so if
        a dead bridge session is reaped *after* the other bridges reported this device stale, nothing would re-check
        the vote against the smaller pool. Returns True if the device was just marked offline."""
        if not self.stale_voters or not self.online or not self.stale_vote_passes(live_ips):
            return False
        self.online = False
        stats.inc("offline_revotes")
        logger.warning(
            f"{self.lp} marked OFFLINE on re-vote after the TCP pool changed "
            f"(stale votes {len(self.stale_voters & set(live_ips))} / quorum {self.stale_quorum(len(set(live_ips)))})"
        )
        return True

    async def handle_entity_update(
        self,
        e_state: EntityState,
        from_pkt: Optional[str] = None,
        bridge_ip: Optional[str] = None,
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
                    # unsupported devices are not parsed
                    return False

            logger.debug(f"{self.lp}{sub_fmt_str} seems to have STALE data (no BT mesh activity)")
            self.stale_voters.add(bridge_ip or "unknown")
            self.num_late_states = len(self.stale_voters)
            tcp_pool = await g.ncync_server.get_dev_tcp_pool()
            live_ips = [d.ip_address for d in tcp_pool]
            votes = len(self.stale_voters & set(live_ips))
            quorum = max(1, self.stale_quorum(len(live_ips)))
            if self.stale_vote_passes(live_ips):
                if self.online:
                    self.online = False
                    logger.warning(
                        f"{self.lp}{sub_fmt_str} marked OFFLINE "
                        f"(stale votes {votes} / quorum {quorum} of {len(live_ips)} tcp nodes)"
                    )
                else:
                    logger.warning(
                        f"{self.lp}{sub_fmt_str} is still marked as {'ONLINE' if self.online else 'OFFLINE'} -> "
                        f"(stale votes {votes} / quorum {quorum} of {len(live_ips)} tcp nodes)"
                    )
                return True
            else:
                logger.debug(f"{self.lp} recently seen: {is_recent} but its marked as shouldnt be offline: "
                             f"stale votes {votes} / quorum {quorum} of {len(live_ips)} tcp nodes")
                return False

        if not self.online:
            logger.info(
                f"{self.lp}{" '{}' ({})".format(e_state.name, e_state.sub_id) if e_state.sub_id > 0 else ''} "
                f"is marked ONLINE."
            )
            self.online = True
        # valid states are used to gauge CyncLAN health, if no valid states are received within a configured time limit
        # the bridge device 'Should restart?' sensor will be turned on. Trying to catch an edge case where CyncLAN stalls
        g.last_valid_state_ts = self.last_valid_state_ts = ts
        self.stale_voters.clear()
        self.num_late_states = 0
        self.entities[e_state.sub_id] = e_state
        g.ncync_server.node_devices[self.id] = self
        return await g.mqtt_client.parse_entity_state(e_state, from_pkt=from_pkt)

    def get_ctrl_msg_id_bytes(self):
        """
        Control packets need a number that gets incremented, it is used as a type of msg ID and
        in calculating the checksum. Result is mod 256 in order to keep it within 0-255.
        """
        id_byte, rollover_byte = self.control_bytes
        # logger.debug(f"{lp} Getting control message ID bytes: ctrl_byte={id_byte} rollover_byte={rollover_byte}")
        id_byte += 1
        if id_byte > 255:
            id_byte = id_byte % 256
            rollover_byte += 1

        self.control_bytes = [id_byte, rollover_byte]
        # logger.debug(f"{lp} new data: ctrl_byte={id_byte} rollover_byte={rollover_byte} // {self.control_bytes=}")
        return self.control_bytes

    async def send_command(self, op: int, cmd_: int, sub_id: int, payload: bytes, m_cb: ControlMessageCallback, lp: str):
        tasks = []
        tcp_pool = await g.ncync_server.get_dev_tcp_pool()
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
                    cmd_code=cmd_,
                    command_payload=payload
                )

                full_packet = PacketBuilder.build_outer_packet(
                    packet_type=0x73,
                    queue_id=bridge_device.queue_id,
                    inner_packet=inner_pkt
                )

                if bridge_device.mitm_mode is True:
                    logger.debug(
                        f"{lp} MITM mode active for this device: {bridge_device.ip_address} (ID: {bridge_device.node.id})"
                        f" not writing data >>> \n\n{full_packet.hex(" ")}")
                else:
                    m_cb.id = cmsg_id
                    m_cb.message = full_packet
                    m_cb.sent_at = time.time()
                    bridge_device.messages.control[cmsg_id] = m_cb
                    tasks.append(bridge_device.write(full_packet))
                    str_appnd = "..."
                    if CYNC_RAW:
                        str_appnd = (f' state to device ({bridge_device.ip_address}[{bridge_device.node.id}|queue_id: {bridge_device.queue_id.hex(" ")}):\n'
                                     f'HEX: {full_packet.hex(" ")}\n'
                                     f'INT: {bytes2list(full_packet)}\n')
                        logger.debug(f"{lp} Sending{str_appnd}")

        if tasks:
            await asyncio.gather(*tasks)

    async def set_fan_percentage(self, perc: int) -> bool:
        """
            Translate a preset fan speed into a Cync brightness value and send it to the device.
        :param perc:
        :return:
        """
        lp = f"{self.lp}set_fan_perc:"
        if not self.is_fan_controller:
            logger.warning(
                f"{lp} Device '{self.name}' ({self.id}) is not a fan controller, cannot set fan percent"
            )
            return False
        try:
            await self.set_brightness(
                perc,
                callback=partial(g.mqtt_client.update_fan_percent, self, perc)
            )
        except asyncio.CancelledError as ce:
            raise ce
        except (OSError, TimeoutError, ValueError) as e:
            # anything else is a bug: let it reach the MQTT message handler, which logs a traceback
            logger.warning(f"{self.lp} Exception occurred while setting fan percent: {e!r}")
            return False
        else:
            return True

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
            await self.set_brightness(
                speed.to_perc(),
                callback=partial(g.mqtt_client.update_fan_speed, self, speed)
            )
        except asyncio.CancelledError as ce:
            raise ce
        except (OSError, TimeoutError, ValueError) as e:
            logger.warning(f"{self.lp} Exception occurred while setting fan speed: {e!r}")
            return False
        else:
            return True

    async def set_power(self, state: int, sub_id: Optional[int] = None):
        lp = f"{self.lp}set_power:"
        if state not in (0, 1):
            logger.error(f"{lp} Invalid state! must be 0 or 1")
            return

        op = 0xD0
        cmd_ = 0x0D
        _sub_id = sub_id if sub_id is not None else 0x00
        payload = struct.pack(">BBBBB", 0x11, 0x02, state, 0x00, 0x00)
        m_cb = ControlMessageCallback(
            msg_id=0x00,
            message=None,
            sent_at=0.0,
            callback=partial(
                g.mqtt_client.update_entity_power, self, state, _sub_id
            ),
        )
        await self.send_command(op, cmd_, _sub_id, payload, m_cb, lp)

    async def set_brightness(self, bri: int, sub_id: Optional[int] = None, callback = None):
        lp = f"{self.lp}set_brightness:"
        if not (0 <= bri <= 100):
            logger.error(f"{lp} Invalid brightness: {bri} must be 0-100")
            return

        op = 0xD2 if self.is_sol_lamp else 0xF0
        cmd_ = 0x10
        _sub_id = sub_id if sub_id is not None else 0x00

        # Payload: 0x11 (command), 0x02, 0x01, brightness, padding
        if self.is_sol_lamp:
            payload = struct.pack(">BBBBB", 0x11, 0x02, bri, 0x00, 0x00)
        else:
            # 8 bytes, all unsigned chars
            payload = struct.pack(">BBBBBBBB", 0x11, 0x02, 0x01, bri, 0xFF, 0xFF, 0xFF, 0xFF)
        if callback is None:
            callback = partial(g.mqtt_client.update_brightness, self, bri)
        m_cb = ControlMessageCallback(
            msg_id=0x00,
            message=None,
            sent_at=0.0,
            callback=callback,
        )

        await self.send_command(op, cmd_, _sub_id, payload, m_cb, lp)

    async def set_temperature(self, temp: int, sub_id: Optional[int] = None):
        lp = f"{self.lp}set_temperature:"
        if temp < 0 or (temp > 100 and temp not in (129, 254)):
            logger.error(f"{lp} Invalid temperature! must be 0-100")
            return

        op = 0xE2 if self.is_sol_lamp else 0xF0
        cmd_ = 0x10
        # cmd_ = 0x0D works for all commands to the dual outlet plug
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
        await self.send_command(op, cmd_, _sub_id, payload, m_cb, lp)

    async def set_rgb(
            self, red: int, green: int, blue: int, sub_id: Optional[int] = None
    ):
        lp = f"{self.lp}set_rgb:"
        if not (0 <= red <= 255) or not (0 <= green <= 255) or not (0 <= blue <= 255):
            logger.error(f"{lp} Invalid RGB value! channels must be 0-255")
            return

        op = 0xF0
        cmd_ = 0x10
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
        await self.send_command(op, cmd_, _sub_id, payload, m_cb, lp)

    async def set_lightshow(self, show: str, sub_id: Optional[int] = None):
        lp = f"{self.lp}set_lightshow:"
        show = show.casefold()
        if show not in FACTORY_EFFECTS_BYTES:
            logger.error(f"{lp} Invalid effect: {show}")
            return

        chosen = FACTORY_EFFECTS_BYTES[show]
        op = 0xE2
        cmd_ = 0x0E
        _sub_id = sub_id if sub_id is not None else 0x00

        # Payload: 0x11, 0x02, 0x07, 0x01, byte1, byte2 (6 bytes)
        payload = struct.pack(">BBBBBB", 0x11, 0x02, 0x07, 0x01, light_show_id(show, self.type), chosen[1])
        m_cb = ControlMessageCallback(
            msg_id=0x00,
            message=None,
            sent_at=0.0,
            # set to black to make it standout
            callback=partial(
                g.mqtt_client.update_rgb, self, (0, 0, 0)
            ),
        )
        await self.send_command(op, cmd_, _sub_id, payload, m_cb, lp)


