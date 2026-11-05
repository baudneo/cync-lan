"""
Cync groups (the rooms and sub-rooms of the Cync app), controlled with ONE mesh packet.

A Home Assistant light group sends one command per member, which the BLE mesh relays one after another, so a room
changes light by light. The Cync app addresses the room's group instead and every member reacts to the same packet.

Addressing: the control packet's ``target`` and ``sub`` bytes are one 16-bit little-endian mesh destination
(``target`` = low byte, ``sub`` = high byte). A device has an address below 0x8000 (``sub`` 0 for a single-endpoint
device); a group's address is the cloud export's ``groupID``, which lives in 0x8000-0xFFFF. The cloud integration
(cync_lights) sends room commands exactly like that (``groupID.to_bytes(2, "little")`` in the same field) through the
Cync cloud's TCP server, see docs/protocol.md section 5.
"""
import asyncio
import logging
from functools import partial
from typing import TYPE_CHECKING, List, Optional, Tuple

from cync_lan.const import CYNC_LOG_NAME
from cync_lan.devices.device import CyncDevice, _run_callbacks
from cync_lan.structs import ControlMessageCallback, GlobalObject

if TYPE_CHECKING:
    from cync_lan.devices.session import CyncTCPSession

__all__ = [
    "CyncGroup", "GROUP_ADDRESS_MIN", "GROUP_ADDRESS_MAX", "LOCAL_GROUP_MIN", "LOCAL_GROUP_MAX", "ROOM_WITH_GROUP_FLAG",
    "is_group_address", "group_uuid", "parse_group_uuid",
]
logger = logging.getLogger(CYNC_LOG_NAME)
g = GlobalObject()

# membership commands are sent this far apart (the app spaces them ~150 ms; the mesh relays them one by one)
PACING_SECS = 0.4
# join flag for a room that also holds one of the device's groups (seen in the app's packets, docs/protocol.md)
ROOM_WITH_GROUP_FLAG = 0x87
LOCAL_GROUP_MIN = 0x8001
LOCAL_GROUP_MAX = 0x80FE
GROUP_ADDRESS_MIN = 0x8000
GROUP_ADDRESS_MAX = 0xFFFF
# MQTT device uuid marker: "<home_id>-g<group_id>" (a device is "<home_id>-<dev_id>[-<sub_id>]")
GROUP_UUID_MARK = "g"


def is_group_address(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and GROUP_ADDRESS_MIN <= value <= GROUP_ADDRESS_MAX


def group_uuid(home_id: int, group_id: int) -> str:
    return f"{home_id}-{GROUP_UUID_MARK}{group_id}"


def parse_group_uuid(device_uuid: str) -> Optional[Tuple[int, int]]:
    """(home_id, group_id) for a "<home_id>-g<group_id>" uuid, else None."""
    parts = device_uuid.split("-")
    if len(parts) != 2 or not parts[1].startswith(GROUP_UUID_MARK):
        return None
    try:
        return int(parts[0]), int(parts[1][len(GROUP_UUID_MARK):])
    except ValueError:
        return None


class CyncGroup:
    """A Cync room / sub-room. Has the same set_* methods as CyncDevice so the MQTT command parser can drive either."""

    # read by CyncDevice.send_command: a group has no TCP session of its own, any bridge of the home relays it
    tcp_session: Optional["CyncTCPSession"] = None
    is_sol_lamp = False
    is_fan_controller = False
    # no per-model kelvin range: the MQTT kelvin conversion falls back to CYNC_MINK / CYNC_MAXK
    metadata = None

    def __init__(self, home_id: int, group_id: int, name: str, member_ids: List[int], home_name: Optional[str] = None,
                 is_subgroup: bool = False, is_local: bool = False):
        if not is_group_address(group_id):
            raise ValueError(f"group id {group_id!r} is not a mesh group address (0x8000-0xFFFF)")
        self.home_id = int(home_id)
        self.id = int(group_id)
        self.name = str(name)
        self.home_name = home_name
        self.member_ids: List[int] = sorted({int(m) for m in member_ids})
        self.is_subgroup = bool(is_subgroup)
        # made by cync-lan (local_groups:), not in the Cync account: cync-lan puts it on the member switches itself
        self.is_local = bool(is_local)
        # resolved by DeviceRegistry.add_group: only members that exist in the config
        self.members: List[CyncDevice] = []
        self.lp = f"{self.name}(group {self.id}):"

    @property
    def hass_id(self) -> str:
        return group_uuid(self.home_id, self.id)

    @property
    def key(self) -> Tuple[int, int]:
        return self.home_id, self.id

    @property
    def address_bytes(self) -> Tuple[int, int]:
        """(target, sub) for the control packet: the group address, low byte first."""
        return self.id & 0xFF, (self.id >> 8) & 0xFF

    # ---- capabilities, from the members
    @property
    def lights(self) -> List[CyncDevice]:
        """Members that take brightness / colour commands (plugs and fan controllers only take power)."""
        return [m for m in self.members if not (m.is_plug or m.is_fan_controller)]

    @property
    def supports_brightness(self) -> bool:
        return bool(self.lights)

    @property
    def supports_temperature(self) -> bool:
        return any(m.supports_temperature for m in self.lights)

    @property
    def supports_rgb(self) -> bool:
        return any(m.supports_rgb for m in self.lights)

    def state(self) -> dict:
        """Aggregate state for MQTT: on if any member is on, brightness = the brightest lit dimmable member."""
        on = False
        bri = None
        for member in self.members:
            entity = (member.entities or {}).get(0)
            if entity is None or not entity.power:
                continue
            on = True
            if member in self.lights and entity.brightness is not None:
                bri = entity.brightness if bri is None else max(bri, entity.brightness)
        out = {"state": "ON" if on else "OFF"}
        if on and bri is not None and self.supports_brightness:
            out["brightness"] = bri
        return out

    # ---- commands: one packet to the group address, then the members' own state callbacks
    async def _send(self, op: int, cmd_: int, payload: bytes, callback, lp: str):
        target, sub = self.address_bytes
        m_cb = ControlMessageCallback(msg_id=0x00, message=None, sent_at=0.0, callback=callback)
        await CyncDevice.send_command(self, op, cmd_, sub, payload, m_cb, lp, target_id=target)

    def _member_callbacks(self, method: str, *args, lights_only: bool = False):
        """One ACK callback that updates every member (optimistically: each also reports its own 0x83 status)."""
        members = self.lights if lights_only else self.members
        cbs = [partial(getattr(g.mqtt_client, method), m, *args) for m in members]
        return partial(_run_callbacks, *cbs)

    async def set_power(self, state: int, sub_id: Optional[int] = None):
        lp = f"{self.lp}set_power:"
        if state not in (0, 1):
            logger.error(f"{lp} Invalid state! must be 0 or 1")
            return
        payload = bytes([0x11, 0x02, state, 0x00, 0x00])
        await self._send(0xD0, 0x0D, payload, self._member_callbacks("update_entity_power", state, 0), lp)

    async def set_brightness(self, bri: int, sub_id: Optional[int] = None, callback=None):
        lp = f"{self.lp}set_brightness:"
        if not (0 <= bri <= 100):
            logger.error(f"{lp} Invalid brightness: {bri} must be 0-100")
            return
        payload = bytes([0x11, 0x02, 0x01, bri, 0xFF, 0xFF, 0xFF, 0xFF])
        if callback is None:
            callback = self._member_callbacks("update_brightness", bri, lights_only=True)
        await self._send(0xF0, 0x10, payload, callback, lp)

    async def set_temperature(self, temp: int, sub_id: Optional[int] = None, bri: Optional[int] = None):
        lp = f"{self.lp}set_temperature:"
        if not 0 <= temp <= 100:
            logger.error(f"{lp} Invalid temperature! must be 0-100")
            return
        if bri is not None and not 0 <= bri <= 100:
            logger.error(f"{lp} Invalid brightness: {bri} must be 0-100")
            return
        payload = bytes([0x11, 0x02, 0x01, 0xFF if bri is None else bri, temp, 0x00, 0x00, 0x00])
        cb = self._member_callbacks("update_temperature", temp, lights_only=True)
        if bri is not None:
            cb = partial(_run_callbacks, cb, self._member_callbacks("update_brightness", bri, lights_only=True))
        await self._send(0xF0, 0x10, payload, cb, lp)

    async def set_rgb(self, red: int, green: int, blue: int, sub_id: Optional[int] = None, bri: Optional[int] = None):
        lp = f"{self.lp}set_rgb:"
        if not all(0 <= c <= 255 for c in (red, green, blue)):
            logger.error(f"{lp} Invalid RGB value! channels must be 0-255")
            return
        if bri is not None and not 0 <= bri <= 100:
            logger.error(f"{lp} Invalid brightness: {bri} must be 0-100")
            return
        payload = bytes([0x11, 0x02, 0x01, 0xFF if bri is None else bri, 0xFE, red, green, blue])
        cb = self._member_callbacks("update_rgb", (red, green, blue), lights_only=True)
        if bri is not None:
            cb = partial(_run_callbacks, cb, self._member_callbacks("update_brightness", bri, lights_only=True))
        await self._send(0xF0, 0x10, payload, cb, lp)

    # ---- local groups: put the group on / take it off the member switches (mimics the Cync app, docs/protocol.md)
    async def sync_members(self, registry, pause: float = PACING_SECS) -> int:
        """
        Make every member join this group. Like the app: a member that is in a room leaves it and joins it again with
        flag 0x87 (a room with a group inside), then joins this group with flag 0x00. Returns the members sent to.
        """
        lp = f"{self.lp}sync:"
        if not self.is_local:
            logger.error(f"{lp} only cync-lan local groups are written to the switches")
            return 0
        for member in self.members:
            room = registry.room_of(member)
            if room is not None and room is not self:
                await member.set_group_membership(room.id, False)
                await asyncio.sleep(pause)
                await member.set_group_membership(room.id, True, ROOM_WITH_GROUP_FLAG)
                await asyncio.sleep(pause)
            await member.set_group_membership(self.id, True, 0x00)
            await asyncio.sleep(pause)
        logger.info(f"{lp} sent the join to {len(self.members)} member(s)")
        return len(self.members)

    async def remove_from_members(self, registry, pause: float = PACING_SECS) -> int:
        """Make every member leave this group; a member's room goes back to flag 0x00 unless it has another group."""
        lp = f"{self.lp}remove:"
        if not self.is_local:
            logger.error(f"{lp} only cync-lan local groups are written to the switches")
            return 0
        for member in self.members:
            await member.set_group_membership(self.id, False)
            await asyncio.sleep(pause)
            room = registry.room_of(member)
            other = [gr for gr in registry.groups_with(member) if gr not in (self, room) and (gr.is_subgroup or gr.is_local)]
            if room is not None and not other:
                await member.set_group_membership(room.id, True, 0x00)
                await asyncio.sleep(pause)
        logger.info(f"{lp} sent the leave to {len(self.members)} member(s)")
        return len(self.members)

    async def set_lightshow(self, show: str, sub_id: Optional[int] = None):
        logger.warning(f"{self.lp}set_lightshow: light shows are not supported on Cync groups, ignoring '{show}'")
