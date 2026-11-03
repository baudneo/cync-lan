"""CYNC_MESH_REFRESH_SECS parsing (baudneo/cync-lan#39). On by default, 0 turns it off."""

import pytest

from cync_lan.const import DEFAULT_MESH_REFRESH_SECS, parse_mesh_refresh_secs


def test_default_is_90_seconds():
    assert DEFAULT_MESH_REFRESH_SECS == 90.0


@pytest.mark.parametrize("raw", [None, "", "  ", "null", "None", "abc", "nan", "inf", "-inf"])
def test_unset_or_unusable_falls_back_to_the_default(raw):
    # the add-on passes "null" when the option is missing; that must not silently turn the refresh off
    assert parse_mesh_refresh_secs(raw) == DEFAULT_MESH_REFRESH_SECS


@pytest.mark.parametrize("raw", ["0", "0.0", 0, -5, "-1"])
def test_zero_or_negative_disables(raw):
    assert parse_mesh_refresh_secs(raw) == 0.0


@pytest.mark.parametrize("raw,expected", [("30", 30.0), (" 45.5 ", 45.5), (120, 120.0), ("90", 90.0)])
def test_explicit_values_are_used(raw, expected):
    assert parse_mesh_refresh_secs(raw) == expected
