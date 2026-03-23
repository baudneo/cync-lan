import asyncio
import datetime
import logging
import random
import time
from functools import partial
from typing import Coroutine, Dict, List, Optional, Union

from cync_lan.const import (
    CYNC_CMD_BROADCASTS,
    CYNC_LOG_NAME,
    CYNC_MAX_TCP_CONN,
    CYNC_RAW,
    CYNC_TCP_WHITELIST,
    DATA_BOUNDARY,
    FACTORY_EFFECTS_BYTES,
    RAW_MSG,
    STREAM_CHUNK_SIZE,
    TCP_BLACKHOLE_DELAY,
)
from cync_lan.metadata.model_info import (
    MULTI_ENDPOINT_TYPES,
    DeviceClassification,
    DeviceTypeInfo,
    device_type_map,
)
from cync_lan.structs import (
    ALL_HEADERS,
    DEVICE_STRUCTS,
    CacheData,
    ControlMessageCallback,
    DeviceStatus,
    EndpointState,
    FanSpeed,
    GlobalObject,
    MeshInfo,
    Messages,
    PhoneAppStructs,
    Tasks,
)
from cync_lan.utils import bytes2list, parse_unbound_firmware_version

__all__ = ["CyncNode", "CyncTCPDevice"]
logger = logging.getLogger(CYNC_LOG_NAME)
g = GlobalObject()


class CyncEndpoint:
    lp = "CyncEndpoint:"
    id: int
    node_id: int
    state: EndpointState


class CyncNode:
    """
    A class to represent the physical Cync device as a bridge/controller
    """

    lp = "CyncNode:"
    id: int = None
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
    endpoints: Optional[Dict[int, EndpointState]] = None

    def __init__(
        self,
        node_id: int,
        dev_type: Optional[int] = None,
        name: Optional[str] = None,
        mac: Optional[str] = None,
        wifi_mac: Optional[str] = None,
        fw_version: Optional[str] = None,
        home_id: Optional[int] = None,
        hvac: Optional[dict] = None,
        endpoints: Optional[Dict[int, "EndpointState"]] = None,
    ):
        self.control_bytes = bytes([0x00, 0x00])
        if node_id is None:
            raise ValueError("ID must be provided to constructor")
        self.id = node_id
        self.endpoints: Optional[Dict[int, "EndpointState"]] = endpoints
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
            name = f"device_{node_id}"
        self.name = name
        self.lp = f"{self.lp}{self.name}({node_id}):"
        self._status: DeviceStatus = DeviceStatus()
        self._mesh_alive_byte: Union[int, str] = 0x00
        if hvac is not None:
            self.hvac = hvac
            self._is_hvac = True

    @property
    def hass_id(self):
        return f"{self.home_id}-{self.id}"

    @property
    def uses_xlink_opcodes(self) -> bool:
        """Return True for older XLink Wi-Fi-direct devices (e.g. C by GE Sol, type 80).

        These devices require 0xD2 for brightness and 0xE2 (sub-cmd 0x05) for CCT,
        rather than the 0xF0 opcodes used by newer Cync mesh devices.
        """
        return bool(self.metadata and self.metadata.opcodes.xlink)

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
            return self.metadata.type == DeviceClassification.LIGHT
        return False

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
        return len(self.endpoints) > 1

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

    async def set_power(self, state: int, sub_id: Optional[int] = None):
        """
        Send raw data to control device state (1=on, 0=off).

            If the device receives the msg and changes state, every TCP device connected will send
            a 0x83 internal status packet, which we use to change HASS device state.
        """
        lp = f"{self.lp}set_power:"
        if state not in (0, 1):
            logger.error(f"{lp} Invalid state! must be 0 or 1")
            return
        # elif state == self.state:
        #     # to stop flooding the network with commands
        #     logger.debug(f"{lp} Device already in power state {state}, skipping...")
        #     return
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
            sub_id if sub_id is not None else 0x00,
            0xD0,
            0x11,
            0x02,
            state,
            0x00,
            0x00,
            "checksum",
            0x7E,
        ]
        bridge_devices: List["CyncTCPDevice"] = random.sample(
            list(g.ncync_server.tcp_devices.values()),
            k=min(CYNC_CMD_BROADCASTS, len(g.ncync_server.tcp_devices)),
        )
        tasks: List[Optional[Union[asyncio.Task, Coroutine]]] = []
        ts = time.time()
        ctrl_idxs = 1, 9
        sent = {}
        for bridge_device in bridge_devices:
            if bridge_device.ready_to_control is True:
                payload = list(header)
                payload.extend(bridge_device.queue_id)
                payload.extend(bytes([0x00, 0x00, 0x00]))
                cmsg_id = bridge_device.get_ctrl_msg_id_bytes()[0]
                inner_struct[ctrl_idxs[0]] = cmsg_id
                inner_struct[ctrl_idxs[1]] = cmsg_id
                checksum = sum(inner_struct[6:-2]) % 256
                inner_struct[-2] = checksum
                payload.extend(inner_struct)
                payload_bytes = bytes(payload)
                m_cb = ControlMessageCallback(
                    msg_id=cmsg_id,
                    message=payload_bytes,
                    sent_at=time.time(),
                    callback=partial(
                        g.mqtt_client.update_endpoint_power, self, state, sub_id
                    ),
                )
                bridge_device.messages.control[cmsg_id] = m_cb
                sent[bridge_device.address] = cmsg_id
                tasks.append(bridge_device.write(payload_bytes))
            else:
                logger.debug(
                    f"{lp} Skipping device: {bridge_device.address} not ready to control"
                )
        if tasks:
            await asyncio.gather(*tasks)
        elapsed = time.time() - ts
        logger.debug(
            f"{lp} Sent power state command for: {self.name} ({self.id}{'/{}'.format(sub_id) if sub_id is not None else ''}), current: {self.state} - new: {state} to "
            f"TCP devices: {sent} in {elapsed:.5f} seconds"
        )

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
                await self.set_brightness(50)
            elif speed == FanSpeed.MEDIUM:
                await self.set_brightness(128)
            elif speed == FanSpeed.HIGH:
                await self.set_brightness(191)
            elif speed == FanSpeed.MAX:
                await self.set_brightness(255)
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

    async def set_brightness(self, bri: int, sub_id: Optional[int] = None):
        """
        Send raw data to control device brightness (0-100). Fans are 0-255.
        """
        """
        73 00 00 00 22 37 96 24 69 60 48 00 7e 17 00 00  s..."7.$i`H.~...
        00 f8 f0 10 00 17 00 00 00 00 07 00 f0 11 02 01  ................
        27 ff ff ff ff 45 7e
        """
        lp = f"{self.lp}set_brightness:"
        if bri < 0 or bri > 100:
            if self.is_fan_controller:
                # fan can be controlled via light control structs: brightness -> max=255, high=191, medium=128, low=50, off=0
                pass
            elif self.is_light or self.is_switch:
                logger.error(f"{lp} Invalid brightness: {bri} must be 0-100")
                return

        # elif bri == self._brightness:
        #     logger.debug(f"{lp} Device already in brightness {bri}, skipping...")
        #     return
        xlink = self.uses_xlink_opcodes
        # XLink devices (e.g. C by GE Sol, type 80): opcode 0xD2 (OP_SET_DEVICE_LUM),
        # power-command packet shape (LEN=0x1F, 3 param bytes).
        # Standard Cync mesh devices: opcode 0xF0, longer packet shape (LEN=0x22).
        op = 0xD2 if xlink else 0xF0
        header = [0x73, 0x00, 0x00, 0x00, 0x1F] if xlink else [115, 0, 0, 0, 34]
        inner_struct = (
            [0x7E, "ctrl_byte", 0x00, 0x00, 0x00, 0xF8, op, 0x0D, 0x00, "ctrl_byte",
             0x00, 0x00, 0x00, 0x00, self.id, sub_id if sub_id is not None else 0x00,
             op, 0x11, 0x02, bri, 0x00, 0x00, "checksum", 0x7E]
            if xlink else
            [126, "ctrl_byte", 0, 0, 0, 248, 240, 16, 0, "ctrl_byte",
             0, 0, 0, 0, self.id, sub_id if sub_id is not None else 0,
             240, 17, 2, 1, bri, 255, 255, 255, 255, "checksum", 126]
        )
        bridge_devices: List["CyncTCPDevice"] = random.sample(
            list(g.ncync_server.tcp_devices.values()),
            k=min(CYNC_CMD_BROADCASTS, len(g.ncync_server.tcp_devices)),
        )
        sent = {}
        tasks: List[Optional[Union[asyncio.Task, Coroutine]]] = []
        ts = time.time()
        ctrl_idxs = 1, 9
        for bridge_device in bridge_devices:
            if bridge_device.ready_to_control is True:
                payload = list(header)
                payload.extend(bridge_device.queue_id)
                payload.extend(bytes([0x00, 0x00, 0x00]))
                cmsg_id = bridge_device.get_ctrl_msg_id_bytes()[0]
                inner_struct[ctrl_idxs[0]] = cmsg_id
                inner_struct[ctrl_idxs[1]] = cmsg_id
                checksum = sum(inner_struct[6:-2]) % 256
                inner_struct[-2] = checksum
                payload.extend(inner_struct)
                payload_bytes = bytes(payload)
                sent[bridge_device.address] = cmsg_id
                m_cb = ControlMessageCallback(
                    msg_id=cmsg_id,
                    message=payload_bytes,
                    sent_at=time.time(),
                    callback=partial(g.mqtt_client.update_brightness, self, bri),
                )
                bridge_device.messages.control[cmsg_id] = m_cb
                tasks.append(bridge_device.write(payload_bytes))
            else:
                logger.debug(
                    f"{lp} Skipping device: {bridge_device.address} not ready to control"
                )
        if tasks:
            await asyncio.gather(*tasks)
        elapsed = time.time() - ts
        logger.debug(
            f"{lp} Sent brightness command, current: {self.brightness} new: {bri} to TCP devices: {sent} in {elapsed:.5f} seconds"
        )

    async def set_temperature(self, temp: int, sub_id: Optional[int] = None):
        """
        Send raw data to control device white temperature (0-100)

            If the device receives the msg and changes state, every TCP device connected will send
            a 0x83 internal status packet, which we use to change HASS device state.
        """
        """
        73 00 00 00 22 37 96 24 69 60 8d 00 7e 36 00 00  s..."7.$i`..~6..
        00 f8 f0 10 00 36 00 00 00 00 07 00 f0 11 02 01  .....6..........
        ff 48 00 00 00 88 7e                             .H....~

                checksum = 0x88 = 136
            0xf0 0x10 0x36 0x07 0xf0 0x11 0x02 0x01 0xff 0x48 = 904 (% 256) = 136
        """
        lp = f"{self.lp}set_temperature:"
        if temp < 0 or (temp > 100 and temp not in (129, 254)):
            logger.error(f"{lp} Invalid temperature! must be 0-100")
            return
        # elif temp == self.temperature:
        #     logger.debug(f"{lp} Device already in temperature {temp}, skipping...")
        #     return
        xlink = self.uses_xlink_opcodes
        # XLink devices (e.g. C by GE Sol, type 80): opcode 0xE2 (OP_SET_DEVICE_CT),
        # sub-command 0x05 selects CCT mode, power-command packet shape (LEN=0x1F).
        # Standard Cync mesh devices: opcode 0xF0, longer packet shape (LEN=0x22).
        op = 0xE2 if xlink else 0xF0
        header = [0x73, 0x00, 0x00, 0x00, 0x1F] if xlink else [115, 0, 0, 0, 34]
        inner_struct = (
            [0x7E, "msg id", 0x00, 0x00, 0x00, 0xF8, op, 0x0D, 0x00, "msg id",
             0x00, 0x00, 0x00, 0x00, self.id, sub_id if sub_id is not None else 0x00,
             op, 0x11, 0x02, 0x05, temp, 0x00, "checksum", 0x7E]
            if xlink else
            [126, "msg id", 0, 0, 0, 248, 240, 16, 0, "msg id",
             0, 0, 0, 0, self.id, sub_id if sub_id is not None else 0,
             240, 17, 2, 1, 0xFF, temp, 0x00, 0x00, 0x00, "checksum", 126]
        )
        bridge_devices: List["CyncTCPDevice"] = random.sample(
            list(g.ncync_server.tcp_devices.values()),
            k=min(CYNC_CMD_BROADCASTS, len(g.ncync_server.tcp_devices)),
        )
        tasks: List[Optional[Union[asyncio.Task, Coroutine]]] = []
        ts = time.time()
        ctrl_idxs = 1, 9
        sent = {}
        for bridge_device in bridge_devices:
            if bridge_device.ready_to_control is True:
                payload = list(header)
                payload.extend(bridge_device.queue_id)
                payload.extend(bytes([0x00, 0x00, 0x00]))
                cmsg_id = bridge_device.get_ctrl_msg_id_bytes()[0]
                inner_struct[ctrl_idxs[0]] = cmsg_id
                inner_struct[ctrl_idxs[1]] = cmsg_id
                checksum = sum(inner_struct[6:-2]) % 256
                inner_struct[-2] = checksum
                payload.extend(inner_struct)
                payload_bytes = bytes(payload)
                sent[bridge_device.address] = cmsg_id
                m_cb = ControlMessageCallback(
                    msg_id=cmsg_id,
                    message=payload_bytes,
                    sent_at=time.time(),
                    callback=partial(g.mqtt_client.update_temperature, self, temp),
                )
                bridge_device.messages.control[cmsg_id] = m_cb
                tasks.append(bridge_device.write(payload_bytes))
            else:
                logger.debug(
                    f"{lp} Skipping device: {bridge_device.address} not ready to control"
                )
        if tasks:
            await asyncio.gather(*tasks)
        elapsed = time.time() - ts
        logger.debug(
            f"{lp} Sent white temperature command, current: {self.temperature} - new: {temp} to TCP "
            f"devices: {sent} in {elapsed:.5f} seconds"
        )

    async def set_rgb(
        self, red: int, green: int, blue: int, sub_id: Optional[int] = None
    ):
        """
        Send raw data to control device RGB color (0-255 for each channel).

            If the device receives the msg and changes state, every TCP device connected will send
            a 0x83 internal status packet, which we use to change HASS device state.
        """
        """
         73 00 00 00 22 37 96 24 69 60 79 00 7e 2b 00 00  s..."7.$i`y.~+..
         00 f8 f0 10 00 2b 00 00 00 00 07 00 f0 11 02 01  .....+..........
         ff fe 00 fb ff 2d 7e                             .....-~

        f0 10 2b 07 f0 11 02 01 ff fe fb ff = 1581 (% 256) = 45
            checksum = 45
        """
        lp = f"{self.lp}set_rgb:"
        if red < 0 or red > 255:
            logger.error(f"{lp} Invalid red value! must be 0-255")
            return
        if green < 0 or green > 255:
            logger.error(f"{lp} Invalid green value! must be 0-255")
            return
        if blue < 0 or blue > 255:
            logger.error(f"{lp} Invalid blue value! must be 0-255")
            return
        _rgb = (red, green, blue)
        # if red == self._r and green == self._g and blue == self._b:
        #     logger.debug(f"{lp} Device already in RGB color {red}, {green}, {blue}, skipping...")
        #     return
        header = [115, 0, 0, 0, 34]
        inner_struct = [
            126,
            "msg id",
            0,
            0,
            0,
            248,
            240,
            16,
            0,
            "msg id",
            0,
            0,
            0,
            0,
            self.id,
            sub_id if sub_id is not None else 0,
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
        bridge_devices: List["CyncTCPDevice"] = random.sample(
            list(g.ncync_server.tcp_devices.values()),
            k=min(CYNC_CMD_BROADCASTS, len(g.ncync_server.tcp_devices)),
        )
        tasks: List[Optional[Union[asyncio.Task, Coroutine]]] = []
        ts = time.time()
        ctrl_idxs = 1, 9
        sent = {}
        for bridge_device in bridge_devices:
            if bridge_device.ready_to_control is True:
                payload = list(header)
                payload.extend(bridge_device.queue_id)
                payload.extend(bytes([0x00, 0x00, 0x00]))
                cmsg_id = bridge_device.get_ctrl_msg_id_bytes()[0]
                inner_struct[ctrl_idxs[0]] = cmsg_id
                inner_struct[ctrl_idxs[1]] = cmsg_id
                checksum = sum(inner_struct[6:-2]) % 256
                inner_struct[-2] = checksum
                payload.extend(inner_struct)
                bpayload = bytes(payload)
                sent[bridge_device.address] = cmsg_id
                m_cb = ControlMessageCallback(
                    msg_id=cmsg_id,
                    message=bpayload,
                    sent_at=time.time(),
                    callback=partial(g.mqtt_client.update_rgb, self, _rgb),
                )
                bridge_device.messages.control[cmsg_id] = m_cb
                tasks.append(bridge_device.write(bpayload))
            else:
                logger.debug(
                    f"{lp} Skipping device: {bridge_device.address} not ready to control"
                )
        if tasks:
            await asyncio.gather(*tasks)
        elapsed = time.time() - ts
        logger.debug(
            f"{lp} Sent RGB command, current: {self.red}, {self.green}, {self.blue} - new: {red}, {green}, {blue} to TCP devices {sent} in {elapsed:.5f} seconds"
        )

    async def set_lightshow(self, show: str, sub_id: Optional[int] = None):
        """
            Set the device into a light show

        :param show:
        :return:
        """

        """

            # candle 0x01 0xf1
        73 00 00 00 20 2d e4 b5 d2 b3 05 00 7e 14 00 00  s... -......~...
        00 f8 [e2 0e 00 14 00 00 00 00 0a                ...........
        00 e2 11 02 07 01 01 f1](chksum data) fd 7e      .........~

        # rainbow 0x02 0x7a
        73 00 00 00 20 2d e4 b5 d2 29 c3 00 7e 07 00 00  s... -...)..~...
        00 f8 e2 0e 00 07 00 00 00 00 0a                 ...........
        00 e2 11 02 07 01 02 7a 7a 7e                    .......zz~

    # cyber 0x43 0x9f
   73 00 00 00 20 2d e4 b5 d2 2a 1b 00 7e 08 00 00  s... -...*..~...
   00 f8 e2 0e 00 08 00 00 00 00 0a                 ...........
   00 e2 11 02 07 01 43 9f e1 7e                    ......C..~

   # fireworks 0x3a 0xda
      73 00 00 00 20 2d e4 b5 d2 2a d7 00 7e 0d 00 00  s... -...*..~...
   00 f8 e2 0e 00 0d 00 00 00 00 0a                 ...........
   00 e2 11 02 07 01 03 da e1 7e                    .........~

   # volcanic 0x04 0xf4
      73 00 00 00 20 2d e4 b5 d2 c3 8c 00 7e 06 00 00  s... -......~...
   00 f8 e2 0e 00 06 00 00 00 00 0a                 ...........
   00 e2 11 02 07 01 04 f4 f5 7e                    .........~

   # aurora 0x05 0x1c
      73 00 00 00 20 2d e4 b5 d2 c4 2d 00 7e 08 00 00  s... -....-.~...
   00 f8 e2 0e 00 08 00 00 00 00 0a                 ...........
   00 e2 11 02 07 01 05 1c 20 7e                    ........ ~

   # happy holidays 0x06 0x54
      73 00 00 00 20 2d e4 b5 d2 c4 96 00 7e 0b 00 00  s... -......~...
   00 f8 e2 0e 00 0b 00 00 00 00 0a                 ...........
   00 e2 11 02 07 01 06 54 5c 7e                    .......T~

   # red white blue 0x07 0x4f
      73 00 00 00 20 2d e4 b5 d2 c4 d0 00 7e 0e 00 00  s... -......~...
   00 f8 e2 0e 00 0e 00 00 00 00 0a                 ...........
   00 e2 11 02 07 01 07 4f 5b 7e                    .......O[~

   # vegas 0x08 0xe3
      73 00 00 00 20 2d e4 b5 d2 c4 e8 00 7e 11 00 00  s... -......~...
   00 f8 e2 0e 00 11 00 00 00 00 0a                 ...........
   00 e2 11 02 07 01 08 e3 f3 7e                    .........~

   # party time 0x09 0x06
      73 00 00 00 20 2d e4 b5 d2 c5 04 00 7e 13 00 00  s... -......~...
   00 f8 e2 0e 00 13 00 00 00 00 0a                 ...........
   00 e2 11 02 07 01 09 06 19 7e                    .........~ 
        """

        lp = f"{self.lp}set_lightshow:"
        header = [115, 0, 0, 0, 32]
        inner_struct = [
            126,
            "msg id",
            0,
            0,
            0,
            248,
            226,
            14,
            0,
            "msg id",
            0,
            0,
            0,
            0,
            self.id,
            sub_id if sub_id is not None else 0,
            226,
            17,
            2,
            # 11 02 (07 01 01 f1)[diff between effects?] fd[cksm]
            7,
            1,
            "byte 1",
            "byte 2",
            "checksum",
            126,
        ]
        show = show.casefold()
        if show not in FACTORY_EFFECTS_BYTES:
            logger.error(f"{lp} Invalid effect: {show}")
            return
        else:
            chosen = FACTORY_EFFECTS_BYTES[show]
        inner_struct[-4] = chosen[0]
        inner_struct[-3] = chosen[1]
        bridge_devices: List["CyncTCPDevice"] = random.sample(
            list(g.ncync_server.tcp_devices.values()),
            k=min(CYNC_CMD_BROADCASTS, len(g.ncync_server.tcp_devices)),
        )
        tasks: List[Optional[Union[asyncio.Task, Coroutine]]] = []
        ts = time.time()
        ctrl_idxs = 1, 9
        sent = {}
        for bridge_device in bridge_devices:
            if bridge_device.ready_to_control is True:
                payload = list(header)
                payload.extend(bridge_device.queue_id)
                payload.extend(bytes([0x00, 0x00, 0x00]))
                cmsg_id = bridge_device.get_ctrl_msg_id_bytes()[0]
                inner_struct[ctrl_idxs[0]] = cmsg_id
                inner_struct[ctrl_idxs[1]] = cmsg_id
                checksum = sum(inner_struct[6:-2]) % 256
                inner_struct[-2] = checksum
                payload.extend(inner_struct)
                bpayload = bytes(payload)
                sent[bridge_device.address] = cmsg_id
                m_cb = ControlMessageCallback(
                    msg_id=cmsg_id,
                    message=bpayload,
                    sent_at=time.time(),
                    callback=partial(asyncio.sleep, 0),
                )
                bridge_device.messages.control[cmsg_id] = m_cb
                tasks.append(bridge_device.write(bpayload))
            else:
                logger.debug(
                    f"{lp} Skipping device: {bridge_device.address} not ready to control"
                )
        if tasks:
            await asyncio.gather(*tasks)
        elapsed = time.time() - ts
        logger.debug(
            f"{lp} Sent light_show / effect command: '{show}' to TCP devices {sent} in {elapsed:.5f} seconds"
        )

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

    def has_state_changed(self, ep_state: EndpointState):
        curr = self.endpoints[ep_state.id]
        return curr != ep_state

    @property
    def current_status(self) -> List[int]:
        """
        Return the current status of the device as a list
        :return: [state, brightness, temperature, red, green, blue]
        """
        ep = self.endpoints.get(0, next(iter(self.endpoints.values())))
        return [
            ep.power,
            ep.brightness,
            ep.temperature,
            ep.red,
            ep.green,
            ep.blue,
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
        # Lazy evaluation: Only runs next() if get(0) returns None.
        # The 'None' inside next() prevents StopIteration crashes.
        ep = self.endpoints.get(0) or next(iter(self.endpoints.values()), None)
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

        ep = self.endpoints.get(0) or next(iter(self.endpoints.values()), None)
        if not ep:
            logger.error(f"{self.lp} Cannot set state, self.endpoints is empty!")
            return

        if value != ep.power:
            ep.power = value

    @property
    def brightness(self):
        ep = self.endpoints.get(0, next(iter(self.endpoints.values())))
        return ep.brightness

    @brightness.setter
    def brightness(self, value: int):
        if value < 0 or value > 255:
            raise ValueError(f"Brightness must be between 0 and 255, got: {value}")
        ep = self.endpoints.get(0, next(iter(self.endpoints.values())))
        if value != ep.brightness:
            ep.brightness = value

    @property
    def temperature(self):
        ep = self.endpoints.get(0, next(iter(self.endpoints.values())))
        return ep.temperature

    @temperature.setter
    def temperature(self, value: int):
        if value < 0 or value > 255:
            raise ValueError(f"Temperature must be between 0 and 255, got: {value}")
        ep = self.endpoints.get(0, next(iter(self.endpoints.values())))
        if value != ep.temperature:
            ep.temperature = value

    @property
    def red(self):
        ep = self.endpoints.get(0, next(iter(self.endpoints.values())))
        return ep.red

    @red.setter
    def red(self, value: int):
        if value < 0 or value > 255:
            raise ValueError(f"Red must be between 0 and 255, got: {value}")
        ep = self.endpoints.get(0, next(iter(self.endpoints.values())))
        if value != ep.red:
            ep.red = value

    @property
    def green(self):
        ep = self.endpoints.get(0, next(iter(self.endpoints.values())))
        return ep.green

    @green.setter
    def green(self, value: int):
        if value < 0 or value > 255:
            raise ValueError(f"Green must be between 0 and 255, got: {value}")
        ep = self.endpoints.get(0, next(iter(self.endpoints.values())))
        if value != ep.green:
            ep.green = value

    @property
    def blue(self):
        ep = self.endpoints.get(0, next(iter(self.endpoints.values())))
        return ep.blue

    @blue.setter
    def blue(self, value: int):
        if value < 0 or value > 255:
            raise ValueError(f"Blue must be between 0 and 255, got: {value}")
        ep = self.endpoints.get(0, next(iter(self.endpoints.values())))
        if value != ep.blue:
            ep.blue = value

    @property
    def rgb(self):
        """Return the RGB color as a list"""
        ep = self.endpoints.get(0, next(iter(self.endpoints.values())))
        return [ep.red, ep.green, ep.blue]

    @rgb.setter
    def rgb(self, value: List[int]):
        if len(value) != 3:
            raise ValueError(f"RGB value must be a list of 3 integers, got: {value}")
        ep = self.endpoints.get(0, next(iter(self.endpoints.values())))
        if value != [ep.red, ep.green, ep.blue]:
            ep.red, ep.green, ep.blue = value

    def __repr__(self):
        return f"<CyncDevice: {self.id}>"

    def __str__(self):
        return f"CyncDevice:{self.id}:"


class CyncTCPDevice:
    """
    A class to interact with a TCP Cync device. It is an async socket reader/writer.
    """

    lp: str = "TCPDevice:"
    known_device_ids: List[Optional[int]]
    tasks: Tasks
    reader: Optional[asyncio.StreamReader]
    writer: Optional[asyncio.StreamWriter]
    messages: Messages
    # keep track of msg ids and if we finished reading data, if not, we need to append the data and then parse it
    read_cache = []
    needs_more_data = False
    is_app: bool

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        address: str,
    ):
        if not address:
            raise ValueError("IP address must be provided to CyncTCPDevice constructor")
        self.lp = f"{address}:"
        self._py_id = id(self)
        self.known_device_ids = []
        self.tasks = Tasks()
        self.is_app = False
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
        self.queue_id: bytes = b""
        self.address: Optional[str] = address
        self.read_lock = asyncio.Lock()
        self.write_lock = asyncio.Lock()
        self._reader: asyncio.StreamReader = reader
        self._writer: asyncio.StreamWriter = writer
        self._closing = False
        self.control_bytes = [0x00, 0x00]

    async def can_connect(self) -> bool:
        """Can this Cync TCP device connect? Based on TCP_WHITELIST and MAX_TCP_CONN"""
        lp = f"{self.lp}"
        tcp_dev_len = len(g.ncync_server.tcp_devices)
        num_attempts = g.ncync_server.tcp_conn_attempts[self.address]
        if (
            (g.ncync_server.shutting_down is True)
            or (tcp_dev_len >= CYNC_MAX_TCP_CONN)
            or (CYNC_TCP_WHITELIST and self.address not in CYNC_TCP_WHITELIST)
        ):
            reason = ""
            if g.ncync_server.shutting_down is True:
                reason = "CyncLAN server is shutting down, "
            _sleep = False
            if tcp_dev_len >= CYNC_MAX_TCP_CONN:
                reason = f"CyncLAN server max ({tcp_dev_len}/{CYNC_MAX_TCP_CONN}) TCP connections reached, "
                _sleep = True
            elif CYNC_TCP_WHITELIST and self.address not in CYNC_TCP_WHITELIST:
                reason = f"IP not in CyncLAN server whitelist -> {CYNC_TCP_WHITELIST}, "
                _sleep = True
            tst_ = (num_attempts == 1) or (num_attempts % 20 == 0)
            lmsg = f"{lp} {reason}rejecting new connection..."
            delay = TCP_BLACKHOLE_DELAY
            if tst_:
                logger.warning(lmsg)
            await asyncio.sleep(delay) if _sleep is True else None
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
            # fixme: maybe?
            return False
        # can create a new device
        logger.debug(f"{self.lp} Created new device: {self.address}")
        self.tasks.receive = asyncio.get_event_loop().create_task(
            self.receive_task(), name=f"receive_task-{self._py_id}"
        )
        self.tasks.callback_cleanup = asyncio.get_event_loop().create_task(
            self.callback_cleanup_task(), name=f"callback_cleanup-{self._py_id}"
        )
        return True

    async def start_tasks(self):
        """Start background tasks safely, ensuring old ones are killed first."""

        # 1. Cleanup existing receive task
        if self.tasks.receive and not self.tasks.receive.done():
            self.tasks.receive.cancel()
            try:
                await self.tasks.receive
            except asyncio.CancelledError:
                pass

        # 2. Cleanup existing callback cleanup task
        if (
            hasattr(self.tasks, "callback_cleanup")
            and self.tasks.callback_cleanup
            and not self.callback_task.done()
        ):
            self.callback_task.cancel()
            try:
                await self.callback_task
            except asyncio.CancelledError:
                pass

        # 3. Start new tasks and SAVE THE REFERENCE
        # Python will garbage collect the task if you don't save it to self!
        self.tasks.receive = asyncio.create_task(
            self.receive_task(), name=f"receive_task-{id(self)}"
        )
        self.tasks.callback_cleanup = asyncio.create_task(
            self.callback_cleanup_task(), name=f"callback_cleanup-{id(self)}"
        )

    # async def stop_tasks(self):
    #     """Call this on disconnect/shutdown"""
    #     if self.tasks.receive:
    #         self.tasks.receive.cancel()
    #     if hasattr(self, 'callback_task') and self.callback_task:
    #         self.callback_task.cancel()

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
                        f"New (current + old) data [length: {len(data)}] // reconstructed: {data_len + old_cdata.data_len == len(data)}"
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
        if pkt_type in DEVICE_STRUCTS.requests:
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
                await self.write(bytes(DEVICE_STRUCTS.responses.auth_ack))
                # MUST SEND a3 before you can ask device for anything over TCP
                # Device sends msg identifier (aka: key), server acks that we have the key and store for future comms.
                await asyncio.sleep(0.5)
                await self.send_a3(queue_id)
            # device wants to connect before accepting commands
            elif pkt_type == 0xC3:
                # conn_time_str = ""
                ack_c3 = bytes(DEVICE_STRUCTS.responses.connection_ack)
                logger.debug(f"{lp} CONNECTION REQUEST, replying...")
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
                ack = DEVICE_STRUCTS.x48_generate_ack(bytes(msg_id))
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
                            # TODO: need to not parse this data if we just issued a command or we do like mesh info and create a voting system
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
                                    node_repr: CyncNode = g.ncync_server.devices.get(
                                        dev_id
                                    )
                                    if node_repr:
                                        dev_name = node_repr.name
                                        # todo: refactor this to be dynamic?
                                        if node_repr.type in MULTI_ENDPOINT_TYPES:
                                            if node_repr.type == 67:
                                                # bri byte is a bitmask for on/off state of endpoints
                                                # since we know the state of up to 8 endpoints at once, parse them all
                                                for (
                                                    e_state_
                                                ) in node_repr.endpoints.values():
                                                    bit_shift = e_state_.id - 1
                                                    e_state_.power = (
                                                        1
                                                        if (bri & (1 << bit_shift))
                                                        else 0
                                                    )
                                                    logger.debug(
                                                        f"{lp} Internal STATUS for {e_state_}{_dbg_msg}"
                                                    )
                                                    await (
                                                        g.ncync_server.handle_endpoint(
                                                            e_state_, from_pkt="0x83"
                                                        )
                                                    )
                                        else:
                                            # Standard single endpoint
                                            e_state = EndpointState(
                                                name=node_repr.name,
                                                node_id=dev_id,
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
                                            await g.ncync_server.handle_endpoint(
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
                ack = DEVICE_STRUCTS.x88_generate_ack(msg_id)
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
                                            self.mesh_info = None
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
                                                node_repr: Optional["CyncNode"] = (
                                                    g.ncync_server.devices.get(dev_id)
                                                )
                                                if node_repr:
                                                    dev_name = node_repr.name
                                                    if loop_num == 1:
                                                        # byte 3 (idx 2) is a device type byte but,
                                                        # it only reports on the first item (itself)
                                                        # convert to int, and it is the same as deviceType from cloud.
                                                        if not self.id:
                                                            self.id = dev_id
                                                            self.lp = f"{self.address}[{self.id}]:"
                                                            logger.debug(
                                                                f"{self.lp}parse:0x{data[0]:02x}: Setting TCP"
                                                                f" device Node ID to: {self.id}"
                                                            )

                                                        elif (
                                                            self.id
                                                            and self.id != dev_id
                                                        ):
                                                            logger.warning(
                                                                f"{lp}parse:0x{data[0]:02x}: node_id MISMATCH "
                                                                f"open an issue on github. current: {self.id} "
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
                                                            for e_state_ in node_repr.endpoints.values():
                                                                bit_shift = (
                                                                    e_state_.id - 1
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
                                                                dev_name = f"'{node_repr.name} - {e_state_.name}' (ID: {dev_id}/{e_state_.id})"
                                                                logger.debug(
                                                                    f"{lp} Mesh state for {e_state_}"
                                                                )
                                                                await g.ncync_server.handle_endpoint(
                                                                    e_state_,
                                                                    from_pkt="0x73",
                                                                )
                                                    else:
                                                        # Standard single endpoint
                                                        e_state = EndpointState(
                                                            name=node_repr.name,
                                                            node_id=dev_id,
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
                                                        await g.ncync_server.handle_endpoint(
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
                                        if self.parse_mesh_status is True:
                                            logger.debug(
                                                f"{lp} Parsing initial connection device status data"
                                            )
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
                                        # Only clear the status once all paginated packets have arrived
                                        if getattr(
                                            self, "_mesh_received", 0
                                        ) >= getattr(self, "_mesh_expected", 0):
                                            logger.debug(
                                                f"{lp} Finished receiving all {getattr(self, '_mesh_expected', 0)} "
                                                f"devices in the mesh."
                                            )
                                            self.parse_mesh_status = False
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
                ack = DEVICE_STRUCTS.x7b_generate_ack(queue_id, msg_id)
                # logger.debug(f"{lp} Sending ACK -> {ack.hex(' ')}")
                await self.write(ack)
        elif pkt_type in PhoneAppStructs.requests:
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
        _rdmsg = ""
        if CYNC_RAW is True:
            _rdmsg = f"\nBYTES: {mesh_info_data}\nHEX: {mesh_info_data.hex(' ')}\nINT: {bytes2list(mesh_info_data)}"
        logger.debug(f"{lp} Requesting ALL device(s) status{_rdmsg}")
        if parse is True:
            self.parse_mesh_status = True
        try:
            await self.write(mesh_info_data)
        except TimeoutError as to_exc:
            logger.error(
                f"{lp} Requesting ALL device(s) status timed out, likely powered off"
            )
            self.parse_mesh_status = False
            raise to_exc
        except Exception as e:
            logger.error(f"{lp} EXCEPTION: {e}", exc_info=True)
            self.parse_mesh_status = False

    async def send_a3(self, q_id: bytes):
        a3_packet = bytes([0xA3, 0x00, 0x00, 0x00, 0x07])
        a3_packet += q_id
        # random 2 bytes
        rand_bytes = self.xa3_msg_id = random.getrandbits(16).to_bytes(2, "big")
        rand_bytes += bytes([0x00])
        self.xa3_msg_id += random.getrandbits(8).to_bytes(1, "big")
        a3_packet += rand_bytes
        logger.debug(f"{self.lp} Sending 0xa3 (want to control) packet...")
        await self.write(a3_packet)
        self.ready_to_control = True
        # send mesh info request
        await asyncio.sleep(1.5)
        await self.ask_for_mesh_info(True)

    async def callback_cleanup_task_old(self):
        """Go through the callback queue and remove any callbacks that are older than 5 minutes"""
        lp = f"{self.lp}callback_clean:"
        logger.debug(f"{lp} Starting background task...")
        delay_mins = 5
        while True:
            try:
                await asyncio.sleep(delay_mins * 60)
                now = time.time()
                for ctrl_msg_id, ctrl_msg in self.messages.control.items():
                    timeout = ctrl_msg.sent_at + (delay_mins * 60)
                    if now > timeout:
                        logger.info(f"{lp} Removing STALE {ctrl_msg}")
                        ctrl_msg.callback = None
                        del self.messages.control[ctrl_msg_id]
                    else:
                        logger.info(f"{lp} Keeping {ctrl_msg}, not timed out yet...")
            except asyncio.CancelledError as can_exc:
                logger.debug(f"{lp} CANCELLED: {can_exc}")
                break
        logger.debug(f"{lp} FINISHED")

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
                                f"dropped the connection (lost power). Removing {dev.address}"
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
        lp = f"{self.address}:close:"
        logger.debug(f"{lp} close() called, Cancelling device tasks...")
        try:
            await self.tasks.cancel_all()
        except Exception as e:
            logger.exception(f"{lp} Exception during device task .cancel_all(): {e}")
        self.closing = True
        try:
            if self.writer:
                async with self.write_lock:
                    self.writer.close()
                    await self.writer.wait_closed()
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
