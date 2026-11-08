"""
Which Cync home is a bridge (TCP session) in? Pure resolution logic, applied in this order:
  a) only one home configured, b) the home's 'bridges:' IP list, c) the 0x23 queue id matched to a device
  'switch_id' (confirmed on hardware; the queue id is not the home id). Nothing else: a bridge none of these can place
stays unresolved (mesh ids are nested across homes, so they are not evidence). All data below is fake.
"""

import pytest
import yaml

from cync_lan import cloud_api
from cync_lan.devices.registry import (
    HomeResolver,
    as_positive_int,
    carry_over_bridges,
    homes_for_queue_id,
    parse_queue_id,
    unresolved_bridge_message,
)
from cync_lan.utils import build_nodes

SMALL, BIG, ODD = 1001, 1002, 1003


def dev(dev_id, dtype=53, **kw):
    d = {"name": f"Dev {dev_id}", "type": dtype, "mac": f"02:00:00:00:0A:{dev_id:02X}",
         "wifi_mac": f"02:00:00:00:0B:{dev_id:02X}"}
    d.update(kw)
    return d


def cfg(**homes_override):
    homes = {
        "Cabin": {"id": SMALL, "access_key": 11111, "devices": {i: dev(i) for i in range(1, 4)}},
        "House": {"id": BIG, "access_key": 22222,
                  "devices": {i: dev(i, dtype=137 if i == 2 else 53) for i in range(1, 7)}},
        "Shed": {"id": ODD, "access_key": 33333, "bridges": ["192.0.2.30"],
                 "devices": {1: dev(1, switch_id=555001), 40: dev(40, dtype=68)}},
    }
    homes.update(homes_override)
    return {"exported_homes": {k: v for k, v in homes.items() if v is not None}}


@pytest.fixture
def reg():
    return build_nodes(cfg())


def qid(n: int) -> bytes:
    return n.to_bytes(4, "big")


# ---- pure helpers
def test_parse_queue_id_is_big_endian():
    assert parse_queue_id(bytes.fromhex("00 00 03 eb")) == 1003
    assert parse_queue_id(bytes.fromhex("0a 1b 2c 3d")) == 0x0A1B2C3D
    assert parse_queue_id(b"") is None
    assert parse_queue_id(None) is None


def test_homes_for_queue_id(reg):
    assert homes_for_queue_id(reg, BIG) == {}  # a home id is not a queue id
    assert set(homes_for_queue_id(reg, 555001)) == {ODD}
    assert "switch_id" in homes_for_queue_id(reg, 555001)[ODD]
    assert homes_for_queue_id(reg, 42) == {}


# ---- a) single home
def test_single_home_resolves_at_creation_and_ignores_everything_else():
    reg = build_nodes(cfg(Cabin=None, Shed=None))
    r = HomeResolver(reg, "192.0.2.99")
    assert r.resolved and r.home_id == BIG and r.method == "single_home"
    assert r.observe_queue_id(qid(SMALL)) is None  # nothing new
    assert r.home_id == BIG


def test_single_home_wins_even_over_a_bridges_list():
    reg = build_nodes(cfg(Cabin=None, House=None))
    r = HomeResolver(reg, "192.0.2.99")  # not in Shed's bridges list
    assert r.home_id == ODD and r.method == "single_home"


# ---- b) manual 'bridges:' override
def test_bridges_override_resolves_at_creation(reg):
    r = HomeResolver(reg, "192.0.2.30")
    assert r.home_id == ODD and r.method == "bridges"


def test_bridges_override_beats_queue_id(reg):
    r = HomeResolver(reg, "192.0.2.30")
    assert r.observe_queue_id(qid(BIG)) is None
    assert r.home_id == ODD and r.method == "bridges"


def test_bridges_override_ignores_ip_listed_in_two_homes(reg):
    reg = build_nodes(cfg(Cabin={"id": SMALL, "bridges": ["192.0.2.30"], "devices": {1: dev(1)}}))
    r = HomeResolver(reg, "192.0.2.30")
    assert not r.resolved


def test_unlisted_ip_is_not_resolved(reg):
    r = HomeResolver(reg, "192.0.2.77")
    assert not r.resolved and r.home_id is None and r.method is None


# ---- c) queue id
def test_queue_id_equal_to_a_home_id_does_not_resolve(reg):
    """The queue id is the device's switchID, never the home id: a coincidence must not place a bridge."""
    r = HomeResolver(reg, "192.0.2.77")
    assert r.observe_queue_id(qid(BIG)) is None and not r.resolved


def test_queue_id_matching_switch_id(reg):
    r = HomeResolver(reg, "192.0.2.77")
    match = r.observe_queue_id(qid(555001))
    assert match.home_id == ODD
    assert "switch_id" in r.queue_id_detail and "Shed" in r.queue_id_detail


def test_queue_id_without_match_stays_unresolved_and_says_so(reg):
    r = HomeResolver(reg, "192.0.2.77")
    assert r.observe_queue_id(qid(0x0A1B2C3D)) is None
    assert not r.resolved
    assert r.queue_id == 0x0A1B2C3D
    assert "0a1b2c3d" in r.queue_id_hex.replace(" ", "")
    assert "no" in r.queue_id_detail.lower()


def test_queue_id_matching_two_homes_is_ambiguous():
    # the same switch_id on a device in Cabin and in Shed
    reg = build_nodes(cfg(Cabin={"id": SMALL, "devices": {1: dev(1, switch_id=555001)}}))
    r = HomeResolver(reg, "192.0.2.77")
    assert r.observe_queue_id(qid(555001)) is None
    assert not r.resolved


def test_unplaced_bridge_stays_unresolved_with_nested_ids():
    """Ids 1..N exist in every home, so a bridge with an unknown queue id is never guessed into one."""
    reg = build_nodes({"exported_homes": {
        "Six": {"id": 2004, "devices": {i: dev(i) for i in range(1, 7)}},
        "FiftyOne": {"id": 2002, "devices": {i: dev(i) for i in range(1, 52)}},
    }})
    r = HomeResolver(reg, "192.0.2.77")
    assert r.observe_queue_id(qid(0xDEADBEEF)) is None
    assert not r.resolved


def test_pin_resolves_from_outside_evidence(reg):
    r = HomeResolver(reg, "192.0.2.77")
    match = r.pin(BIG, "bridges", "test")
    assert match.home_id == BIG and r.method == "bridges"
    assert r.pin(SMALL, "bridges", "x") is None  # already resolved, first answer sticks
    assert r.home_id == BIG


def test_pin_unknown_home_rejected(reg):
    r = HomeResolver(reg, "192.0.2.77")
    with pytest.raises(ValueError):
        r.pin(9999, "bridges", "x")


def test_unresolved_bridge_message_tells_user_what_to_do(reg):
    msg = unresolved_bridge_message(reg, 0xDEADBEEF, "192.0.2.77")
    for needle in ("Cabin", "House", "Shed", "192.0.2.77", "bridges:", "docs/multi_home.md", "deadbeef", "re-export"):
        assert needle in msg, needle


# ---- exporter: switch_id and carrying over 'bridges:'
@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setattr(cloud_api, "CYNC_CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(cloud_api, "CYNC_EXPORT_SOURCE", "file")
    obj = object.__new__(cloud_api.CyncCloudAPI)
    obj.lp = "test"
    return obj


def bulb(raw_id, name="Bulb", **kw):
    d = {"deviceID": raw_id, "displayName": name, "mac": "02:00:00:00:0C:01", "deviceType": 53,
         "firmwareVersion": "10209"}
    d.update(kw)
    return d


def raw_home(*bulbs, name="Cabin", home_id=SMALL):
    return {"name": name, "id": home_id, "product_id": "p", "access_key": 11111, "mac": "m",
            "properties": {"bulbsArray": list(bulbs)}}


async def test_export_writes_switch_id_when_cloud_has_one(api):
    out = await api._parse_raw_export([raw_home(
        bulb("169573386001", "Has", switchID=555001),
        bulb("169573386002", "Zero", switchID=0),
        bulb("169573386003", "None"),
        bulb("169573386004", "Junk", switchID="abc"),
    )])
    devs = out["exported_homes"]["Cabin"]["devices"]
    assert devs[1]["switch_id"] == 555001
    assert "switch_id" not in devs[2] and "switch_id" not in devs[3] and "switch_id" not in devs[4]
    # and build_nodes reads it back
    assert build_nodes(out).get_device(SMALL, 1).switch_id == 555001


def test_carry_over_bridges_matches_by_home_id():
    new = {"exported_homes": {"Cabin (renamed)": {"id": SMALL, "devices": {}},
                              "House": {"id": BIG, "devices": {}}}}
    old = {"exported_homes": {"Cabin": {"id": str(SMALL), "bridges": ["192.0.2.10"]},
                              "House": {"id": BIG},
                              "Gone": {"id": 9999, "bridges": ["192.0.2.99"]}}}
    assert carry_over_bridges(new, old) == 1
    assert new["exported_homes"]["Cabin (renamed)"]["bridges"] == ["192.0.2.10"]
    assert "bridges" not in new["exported_homes"]["House"]


@pytest.mark.parametrize("old", [None, {}, "junk", {"exported_homes": None}, {"exported_homes": {"x": "y"}},
                                 {"exported_homes": {"x": {"id": "abc", "bridges": ["192.0.2.1"]}}}])
def test_carry_over_bridges_tolerates_unusable_old_config(old):
    new = {"exported_homes": {"Cabin": {"id": SMALL, "devices": {}}}}
    assert carry_over_bridges(new, old) == 0
    assert "bridges" not in new["exported_homes"]["Cabin"]


def test_carry_over_bridges_legacy_key_and_does_not_overwrite_new_value():
    new = {"exported_homes": {"Cabin": {"id": SMALL, "bridges": ["192.0.2.5"]}}}
    old = {"account data": {"Cabin": {"id": SMALL, "bridges": ["192.0.2.10"]}}}
    assert carry_over_bridges(new, old) == 0
    assert new["exported_homes"]["Cabin"]["bridges"] == ["192.0.2.5"]


async def test_export_config_file_keeps_bridges_from_existing_config(tmp_path, monkeypatch):
    src = tmp_path / "source.yaml"
    src.write_text(yaml.dump([raw_home(bulb("169573386001", "Lamp"))]))
    out_file = tmp_path / "cync_mesh.yaml"
    out_file.write_text(yaml.dump({"exported_homes": {"Cabin": {
        "id": SMALL, "bridges": ["192.0.2.10"], "devices": {1: {"name": "Old"}}}}}))
    monkeypatch.setattr(cloud_api, "CYNC_CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(cloud_api, "CYNC_EXPORT_SOURCE", str(src))
    monkeypatch.setattr(cloud_api, "CYNC_CONFIG_FILE_PATH", str(out_file))
    monkeypatch.setattr(cloud_api, "CYNC_OVERWRITE_CONFIG_FILE", True)
    api = object.__new__(cloud_api.CyncCloudAPI)
    api.lp = "test"
    assert await api.export_config_file() is True
    written = yaml.safe_load(out_file.read_text())
    home = written["exported_homes"]["Cabin"]
    assert home["bridges"] == ["192.0.2.10"]
    assert home["devices"][1]["name"] == "Lamp"


# ---- review fixes (2026-11-04)
@pytest.mark.parametrize("raw, want", [
    (5, 5), ("7", 7), (" 8 ", 8),
    (0, None), ("0", None), (-3, None), ("-3", None), (2.0, None), (12.7, None), (True, None), ("x", None),
    (None, None), ([1], None), ("²", None), ("１２", 12),
])
def test_as_positive_int_is_the_one_rule_for_ids(raw, want):
    """Home ids, config switch_ids and the cloud switchID all go through this one rule (they used to disagree)."""
    assert as_positive_int(raw) == want


def test_cloud_switch_id_uses_the_same_rule():
    assert cloud_api._cloud_switch_id(12.7) is None  # was truncated to 12
    assert cloud_api._cloud_switch_id("300000222") == 300000222
    assert cloud_api._cloud_switch_id(0) is None


def test_zero_switch_id_in_the_config_is_silently_absent(caplog):
    c = cfg()
    c["exported_homes"]["Shed"]["devices"][1]["switch_id"] = "0"
    with caplog.at_level("WARNING"):
        assert build_nodes(c).get_device(ODD, 1).switch_id is None
    assert "switch_id" not in caplog.text


def test_carry_over_reads_the_same_config_section_as_the_parser():
    """A config with both sections: build_nodes reads 'account data', so the bridges must come from there too."""
    old = {
        "account data": {"House": {"id": BIG, "bridges": ["192.0.2.10"], "devices": {}}},
        "exported_homes": {"House": {"id": BIG, "bridges": ["192.0.2.99"], "devices": {}}},
    }
    new = {"exported_homes": {"House": {"id": BIG, "devices": {}}}}
    assert carry_over_bridges(new, old) == 1
    assert new["exported_homes"]["House"]["bridges"] == ["192.0.2.10"]
