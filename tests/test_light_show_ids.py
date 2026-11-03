"""Factory light-show IDs by deviceType.

On a deviceType 75 (24' Cafe Lights, fw 1.0.516) each ID was sent one at a time and checked three ways: the status code the device
reported, the Cync app's highlighted tile, and the string itself. Fireworks was the only one that differs from the table: 0x3A did
nothing there (also with the table's own last byte 0xDA), 0x03 ran Fireworks (status 0x82).
"""

import pytest

from cync_lan.const import FACTORY_EFFECTS_BYTES, light_show_id


def test_fireworks_keeps_0x3a_by_default():
    assert light_show_id("fireworks", None) == 0x3A
    assert light_show_id("fireworks", 137) == 0x3A


def test_fireworks_is_0x03_on_type_75():
    assert light_show_id("fireworks", 75) == 0x03


@pytest.mark.parametrize("show", [s for s in FACTORY_EFFECTS_BYTES if s != "fireworks"])
def test_other_shows_are_the_same_on_type_75(show):
    assert light_show_id(show, 75) == FACTORY_EFFECTS_BYTES[show][0]
