"""Light shows, music shows and the active-effect code (op 0xE2 / cmd 0x0E "run mode").

Every expected value below was measured on a deviceType 75 (24' Cafe Lights, fw 1.0.516): the command was sent, the device's own
status code read back, and the Cync app's highlighted tile plus the string itself checked by eye. See docs/protocol.md, run modes.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from cync_lan import effects as fx
from cync_lan import mqtt_client as m
from cync_lan.const import FACTORY_EFFECTS_BYTES
from cync_lan.metadata.model_info import device_type_map


# ---- light show IDs
@pytest.mark.parametrize(
    "name, index",
    [("candle", 1), ("rainbow", 2), ("fireworks", 3), ("volcanic", 4), ("aurora", 5), ("happy_holidays", 6),
     ("red_white_blue", 7), ("vegas", 8), ("party_time", 9), ("cyber", 0x43)],
)
def test_light_show_commands_on_type_75(name, index):
    assert fx.effect_command(name, 75) == (fx.RUN_MODE_LIGHT_SHOW, index)


def test_fireworks_keeps_0x3a_on_other_types():
    assert fx.effect_command("fireworks") == (fx.RUN_MODE_LIGHT_SHOW, 0x3A)
    assert fx.effect_command("fireworks", 137) == (fx.RUN_MODE_LIGHT_SHOW, 0x3A)


@pytest.mark.parametrize(
    "name, index",
    [("music_midnight", 1), ("music_earth_tones", 2), ("music_heat_wave", 3), ("music_solar_flare", 4),
     ("music_breeze", 5), ("music_tropical", 6), ("music_spectrum", 7), ("music_supernova", 8)],
)
def test_music_show_commands(name, index):
    assert fx.effect_command(name) == (fx.RUN_MODE_MUSIC_SHOW, index)


def test_custom_slots_start_at_index_10_in_both_modes():
    assert fx.effect_command("custom_light_1") == (fx.RUN_MODE_LIGHT_SHOW, 10)
    assert fx.effect_command("custom_light_23") == (fx.RUN_MODE_LIGHT_SHOW, 32)
    assert fx.effect_command("custom_music_1") == (fx.RUN_MODE_MUSIC_SHOW, 10)
    assert fx.effect_command("custom_music_10") == (fx.RUN_MODE_MUSIC_SHOW, 19)


@pytest.mark.parametrize("name", ["custom_light_0", "custom_light_24", "custom_music_11", "custom_music_x", "music_", "frogger", ""])
def test_unknown_effects_have_no_command(name):
    assert fx.effect_command(name) is None


def test_stop_show_exits_the_running_show():
    assert fx.effect_command(fx.STOP_SHOW) == (fx.RUN_MODE_EXIT, 0)


def test_names_are_case_insensitive():
    assert fx.effect_command("Music_Supernova") == (fx.RUN_MODE_MUSIC_SHOW, 8)


# ---- packet
def test_run_mode_payload_layout():
    assert fx.run_mode_payload(fx.RUN_MODE_MUSIC_SHOW, 8, 0x5A) == bytes([0x11, 0x02, 0x07, 0x02, 0x08, 0x5A])
    assert fx.run_mode_payload(fx.RUN_MODE_LIGHT_SHOW, 0x43, 0x9F) == bytes([0x11, 0x02, 0x07, 0x01, 0x43, 0x9F])


# ---- the active-effect code (0x43 status record byte 6)
@pytest.mark.parametrize(
    "code, name",
    [(0x80, "candle"), (0x81, "rainbow"), (0x82, "fireworks"), (0x88, "party_time"), (0xE3, "cyber"),
     (0x89, "custom_light_1"), (0x9F, "custom_light_23"),
     (0xA0, "music_midnight"), (0xA7, "music_supernova"), (0xA9, "custom_music_1"), (0xB2, "custom_music_10")],
)
def test_status_code_names_the_running_effect(code, name):
    assert fx.effect_from_status(code, 75) == name


@pytest.mark.parametrize("code", [None, 0x00, 0x3C, 0x64, 0xFE, 0xA8, 0xB3, 0x65])
def test_white_rgb_and_unused_codes_are_no_effect(code):
    """0-100 = white temperature, 0xFE = RGB, 0xA8 (index 9) and 0xB3 (index 20) never answered."""
    assert fx.effect_from_status(code) is None


def test_every_command_round_trips_through_its_status_code():
    for name in fx.effect_names(dynamic=True):
        mode, index = fx.effect_command(name, 75)
        if mode == fx.RUN_MODE_EXIT:
            continue
        code = 0xE3 if (mode, index) == (fx.RUN_MODE_LIGHT_SHOW, 0x43) else (0x80 if mode == fx.RUN_MODE_LIGHT_SHOW else 0xA0) + index - 1
        assert fx.effect_from_status(code, 75) == name


def test_effect_lists():
    plain = fx.effect_names(dynamic=False)
    full = fx.effect_names(dynamic=True)
    assert set(FACTORY_EFFECTS_BYTES) <= set(plain) and fx.STOP_SHOW in plain
    # custom LIGHT shows run on a plain colour bulb too (tested on a deviceType 171 Full Color A19); music shows are
    # Dynamic Effects only (the app refuses them for that bulb: "Switch to a Dynamic Effects Product to Use Music Shows")
    assert {"custom_light_1", "custom_light_23"} <= set(plain)
    assert not any(n.startswith(("music_", "custom_music_")) for n in plain)
    assert {"music_supernova", "custom_music_10", "custom_light_23"} <= set(full)


# ---- parse_entity_state
class _Server:
    def __init__(self):
        self.node_devices = {}


def _node(metadata, rgb=True):
    entity = SimpleNamespace(power=1, brightness=64, temperature=0xA7, red=0, green=0, blue=0, motion=0)
    return SimpleNamespace(
        id=1, type=75, hass_id="123-1", entities={0: entity}, metadata=metadata, is_fan_controller=False, is_plug=False,
        is_switch=False, supports_rgb=rgb, supports_temperature=True,
    ), entity


@pytest_asyncio.fixture
async def client():
    m.MQTTClient._instance = None
    m.g.ncync_server = _Server()
    m.g.env = SimpleNamespace(app_mitm_logging=False)
    c = m.MQTTClient()
    c.pub_entity_state = AsyncMock(return_value=True)
    return c


async def test_state_reports_the_running_effect(client):
    node, entity = _node(metadata=device_type_map[75])
    m.g.ncync_server.node_devices[1] = node
    entity.dev_id, entity.sub_id = 1, 0
    await client.parse_entity_state(entity)
    payload = client.pub_entity_state.await_args.args[1]
    assert b'"effect": "music_supernova"' in payload


async def test_rgb_state_clears_the_effect(client):
    node, entity = _node(metadata=device_type_map[75])
    entity.temperature = 0xFE
    m.g.ncync_server.node_devices[1] = node
    entity.dev_id, entity.sub_id = 1, 0
    await client.parse_entity_state(entity)
    payload = client.pub_entity_state.await_args.args[1]
    assert b'"effect": null' in payload and b'"color_mode": "rgb"' in payload
