"""Run modes: light shows, music shows and the active-effect code.

Command: op 0xE2, cmd 0x0E, inner payload ``11 02 07 <mode> <index> <byte>`` (what ``set_lightshow`` sends). Mode 0 exits the
running show, 1 runs a light show, 2 a music show. Any last byte works for every show tested (homebridge-cync-app sends a random
nonce there, ``buildRunModePacket``).

Status: byte 6 of a 0x43 status record (the "color temp" byte) says what is running: 0-100 white temperature, 0xFE RGB,
0x80 + index - 1 a light show (Cyber, index 0x43, reports 0xE3), 0xA0 + index - 1 a music show.

Light-show indexes come from FACTORY_EFFECTS_BYTES, per deviceType (Fireworks is 0x03 on type 75, see
const.LIGHT_SHOW_ID_OVERRIDES). Measured one by one on a deviceType 75 (24' Cafe Lights, fw 1.0.516): each command sent, the status code read back, the Cync app's
highlighted tile and the string itself checked. Custom shows (the app's Custom tab) start at index 10 in both modes; with every
slot the app allows filled, light shows ran at 10-32 and music shows at 10-19, and 33 / 20 did nothing. Index 9 in music mode
never answered. Other device types are untested. See docs/protocol.md.
"""

from typing import Dict, List, Optional, Tuple

from cync_lan.const import FACTORY_EFFECTS_BYTES, light_show_id

RUN_MODE_EXIT = 0x00
RUN_MODE_LIGHT_SHOW = 0x01
RUN_MODE_MUSIC_SHOW = 0x02

STOP_SHOW = "stop_show"
CUSTOM_FIRST_INDEX = 10
CUSTOM_LIGHT_SHOW_SLOTS = 23  # indexes 10-32
CUSTOM_MUSIC_SHOW_SLOTS = 10  # indexes 10-19 (the app allows 10)

LIGHT_SHOW_IDS: Dict[str, int] = {name: ids[0] for name, ids in FACTORY_EFFECTS_BYTES.items()}


def light_show_ids(dev_type: Optional[int] = None) -> Dict[str, int]:
    """Factory light-show indexes for this deviceType (Fireworks differs on type 75, see const.LIGHT_SHOW_ID_OVERRIDES)."""
    return {name: light_show_id(name, dev_type) for name in FACTORY_EFFECTS_BYTES}

MUSIC_SHOW_IDS: Dict[str, int] = {
    "music_midnight": 1,
    "music_earth_tones": 2,
    "music_heat_wave": 3,
    "music_solar_flare": 4,
    "music_breeze": 5,
    "music_tropical": 6,
    "music_spectrum": 7,
    "music_supernova": 8,
}
_CUSTOM = (
    ("custom_light_", RUN_MODE_LIGHT_SHOW, CUSTOM_LIGHT_SHOW_SLOTS),
    ("custom_music_", RUN_MODE_MUSIC_SHOW, CUSTOM_MUSIC_SHOW_SLOTS),
)
_STATUS_BASE = {RUN_MODE_LIGHT_SHOW: 0x80, RUN_MODE_MUSIC_SHOW: 0xA0}
_CYBER_STATUS = 0xE3


def effect_names(dynamic: bool) -> List[str]:
    """The HA effect list. Every color light gets the factory light shows; dynamic (Dynamic Effects) devices also get the music
    shows and the user's custom show slots, the only kind tested so far."""
    names = list(LIGHT_SHOW_IDS)
    if dynamic:
        names += [f"custom_light_{n}" for n in range(1, CUSTOM_LIGHT_SHOW_SLOTS + 1)]
        names += list(MUSIC_SHOW_IDS)
        names += [f"custom_music_{n}" for n in range(1, CUSTOM_MUSIC_SHOW_SLOTS + 1)]
    return names + [STOP_SHOW]


def effect_command(name: str, dev_type: Optional[int] = None) -> Optional[Tuple[int, int]]:
    """Effect name -> (run mode, index) on this deviceType, or None if it is not a known effect."""
    name = name.casefold()
    if name == STOP_SHOW:
        return RUN_MODE_EXIT, 0x00
    lights = light_show_ids(dev_type)
    if name in lights:
        return RUN_MODE_LIGHT_SHOW, lights[name]
    if name in MUSIC_SHOW_IDS:
        return RUN_MODE_MUSIC_SHOW, MUSIC_SHOW_IDS[name]
    for prefix, mode, slots in _CUSTOM:
        slot = name[len(prefix):]
        if name.startswith(prefix) and slot.isdigit() and 1 <= int(slot) <= slots:
            return mode, CUSTOM_FIRST_INDEX + int(slot) - 1
    return None


def effect_from_status(code: Optional[int], dev_type: Optional[int] = None) -> Optional[str]:
    """Status byte 6 -> the running effect's name; None for white (0-100), RGB (0xFE) or a code no known effect reports."""
    if code is None:
        return None
    if code == _CYBER_STATUS:
        return "cyber"
    for mode, base in _STATUS_BASE.items():
        if base <= code < base + 0x20:
            index = code - base + 1
            table = light_show_ids(dev_type) if mode == RUN_MODE_LIGHT_SHOW else MUSIC_SHOW_IDS
            for name, idx in table.items():
                if idx == index:
                    return name
            for prefix, m, slots in _CUSTOM:
                if m == mode and CUSTOM_FIRST_INDEX <= index < CUSTOM_FIRST_INDEX + slots:
                    return f"{prefix}{index - CUSTOM_FIRST_INDEX + 1}"
    return None


def run_mode_payload(mode: int, index: int, last: int) -> bytes:
    """Inner payload of a run-mode command: ``11 02 07 <mode> <index> <last>``."""
    return bytes([0x11, 0x02, 0x07, mode & 0xFF, index & 0xFF, last & 0xFF])
