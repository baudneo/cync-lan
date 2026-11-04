"""
Which Cync home is a bridge (TCP session) in? Pure resolution logic, applied in this order:
  a) only one home configured, b) the home's 'bridges:' IP list, c) the 0x23 queue id matched to a
  home id or a device 'switch_id' (switch_id confirmed on hardware), d) a fingerprint of the mesh ids the bridge reports.
All data below is fake.
"""

import pytest
import yaml

from cync_lan import cloud_api
from cync_lan.devices.registry import (
    HomeResolver,
    ambiguity_message,
    as_positive_int,
    carry_over_bridges,
    format_ids,
    home_fits,
    homes_for_queue_id,
    parse_queue_id,
    plausible_homes,
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
    assert set(homes_for_queue_id(reg, BIG)) == {BIG}
    assert set(homes_for_queue_id(reg, 555001)) == {ODD}
    assert "switch_id" in homes_for_queue_id(reg, 555001)[ODD]
    assert homes_for_queue_id(reg, 42) == {}


def test_format_ids_collapses_runs():
    assert format_ids([5, 1, 2, 3, 7, 8, 3]) == "1-3, 5, 7-8"
    assert format_ids([]) == "none"


def test_home_fits_counts_reported_ids_only(reg):
    fits = home_fits(reg, [1, 2, 3])
    assert (fits[SMALL].lacking, fits[SMALL].unreported) == (frozenset(), 0)
    assert (fits[BIG].lacking, fits[BIG].unreported) == (frozenset(), 3)
    assert (fits[ODD].lacking, fits[ODD].unreported) == (frozenset({2, 3}), 1)
    # absence is not evidence: House is NOT excluded because it also has 4-6 nobody reported. Shed is: it lacks two
    # reported ids, more than Cabin (which fits) has unreported ids (none)
    assert plausible_homes(fits) == {SMALL, BIG}
    # an id no home knows (e.g. added after the export, beyond every home) is no evidence either way
    assert plausible_homes(home_fits(reg, [99])) == {SMALL, BIG, ODD}
    # one id unique to one home is not proof: the other homes may just be missing a device in the config
    assert plausible_homes(home_fits(reg, [40])) == {SMALL, BIG, ODD}


def test_plausible_homes_when_no_home_fits_keeps_every_home(reg):
    # 40 is only in Shed, 2-3 are not in Shed: no home has all of them, so nothing can be ruled out
    assert plausible_homes(home_fits(reg, [2, 3, 40])) == {SMALL, BIG, ODD}


# ---- a) single home
def test_single_home_resolves_at_creation_and_ignores_everything_else():
    reg = build_nodes(cfg(Cabin=None, Shed=None))
    r = HomeResolver(reg, "192.0.2.99")
    assert r.resolved and r.home_id == BIG and r.method == "single_home"
    assert r.observe_queue_id(qid(SMALL)) is None  # nothing new
    assert r.observe_bridge(40, 68) is None
    assert r.home_id == BIG


def test_single_home_wins_even_over_a_bridges_list():
    reg = build_nodes(cfg(Cabin=None, House=None))
    r = HomeResolver(reg, "192.0.2.99")  # not in Shed's bridges list
    assert r.home_id == ODD and r.method == "single_home"


# ---- b) manual 'bridges:' override
def test_bridges_override_resolves_at_creation(reg):
    r = HomeResolver(reg, "192.0.2.30")
    assert r.home_id == ODD and r.method == "bridges"


def test_bridges_override_beats_queue_id_and_fingerprint(reg):
    r = HomeResolver(reg, "192.0.2.30")
    assert r.observe_queue_id(qid(BIG)) is None
    assert r.observe_bridge(5, 53) is None
    assert r.observe_ids([4, 5, 6]) is None
    assert r.home_id == ODD and r.method == "bridges"


def test_bridges_override_ignores_ip_listed_in_two_homes(reg):
    reg = build_nodes(cfg(Cabin={"id": SMALL, "bridges": ["192.0.2.30"], "devices": {1: dev(1)}}))
    r = HomeResolver(reg, "192.0.2.30")
    assert not r.resolved


def test_unlisted_ip_is_not_resolved(reg):
    r = HomeResolver(reg, "192.0.2.77")
    assert not r.resolved and r.home_id is None and r.method is None


# ---- c) queue id
def test_queue_id_matching_home_id(reg):
    r = HomeResolver(reg, "192.0.2.77")
    match = r.observe_queue_id(qid(BIG))
    assert match is not None and match.home_id == BIG and match.method == "queue_id"
    assert r.home_id == BIG and r.queue_id == BIG
    assert "House" in r.queue_id_detail


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
    # a device switch_id in Cabin that equals House's home id
    reg = build_nodes(cfg(Cabin={"id": SMALL, "devices": {1: dev(1, switch_id=BIG)}}))
    r = HomeResolver(reg, "192.0.2.77")
    assert r.observe_queue_id(qid(BIG)) is None
    assert not r.resolved


def test_queue_id_beats_fingerprint(reg):
    r = HomeResolver(reg, "192.0.2.77")
    r.observe_queue_id(qid(SMALL))
    assert r.observe_ids([5]) is None  # 5 only exists in House, but the queue id already decided
    assert r.home_id == SMALL and r.method == "queue_id"


# ---- d) fingerprint
def test_fingerprint_bridge_id_unique_to_one_home_needs_the_rest_of_that_home(reg):
    r = HomeResolver(reg, "192.0.2.77")
    # 40 is only in Shed, but on its own that could also be a Cabin/House device missing from the config
    assert r.observe_bridge(40, 68) is None
    assert r.candidates == {SMALL, BIG, ODD}
    # Shed's other device reports too: every Shed id is accounted for, the others lack id 40
    match = r.observe_ids([1])
    assert match.home_id == ODD and match.method == "fingerprint"


def test_fingerprint_bridge_type_counts_as_evidence_but_not_as_proof(reg):
    r = HomeResolver(reg, "192.0.2.77")
    # id 2 exists in Cabin (type 53) and House (type 137): Cabin gets one point against it, not more
    assert r.observe_bridge(2, 137) is None
    assert r.fits[SMALL].type_mismatch and not r.fits[BIG].type_mismatch
    assert r.candidates == {SMALL, BIG, ODD}
    assert r.observe_ids(range(1, 7)).home_id == BIG


def test_fingerprint_type_decides_between_two_fully_reported_homes():
    reg = build_nodes({"exported_homes": {
        "Cabin": {"id": SMALL, "devices": {i: dev(i) for i in range(1, 4)}},
        "House": {"id": BIG, "devices": {i: dev(i, dtype=137 if i == 1 else 53) for i in range(1, 4)}},
    }})
    r = HomeResolver(reg, "192.0.2.77")
    assert r.observe_bridge(1, 137) is None  # House still has 2 and 3 unreported
    assert r.observe_ids([1, 2, 3]).home_id == BIG


def test_fingerprint_type_unknown_or_mismatching_everywhere_falls_back_to_id(reg):
    r = HomeResolver(reg, "192.0.2.77")
    assert r.observe_bridge(2, 0) is None  # type byte 0 = unknown
    assert not any(f.type_mismatch for f in r.fits.values())
    r2 = HomeResolver(reg, "192.0.2.77")
    assert r2.observe_bridge(2, 200) is None  # no home has type 200 at id 2: id-only evidence
    assert not any(f.type_mismatch for f in r2.fits.values())
    assert r2.candidates == r.candidates == {SMALL, BIG, ODD}


def test_fingerprint_reported_ids_narrow_until_one_home(reg):
    r = HomeResolver(reg, "192.0.2.77")
    assert r.observe_bridge(1, 53) is None
    assert r.candidates == {SMALL, BIG, ODD}
    assert r.observe_ids([1, 2, 3]) is None  # Shed lacks 2 and 3, and Cabin fits with nothing unreported
    assert r.candidates == {SMALL, BIG}
    # 6 is only in House, but House still has 4 and 5 unreported: Cabin may just be missing a device in the config
    assert r.observe_ids([6]) is None
    assert r.candidates == {SMALL, BIG}
    match = r.observe_ids([4, 5])
    assert match.home_id == BIG and r.method == "fingerprint"
    assert "'Cabin' (1001) lacks reported id(s) 4-6" in match.detail


def test_nested_ids_bridge_in_smallest_home_stays_ambiguous(reg):
    """Absence is not evidence: a Cabin bridge reports 1-3, all of which House also has."""
    r = HomeResolver(reg, "192.0.2.77")
    r.observe_queue_id(qid(0xDEADBEEF))
    r.observe_bridge(1, 53)
    r.observe_ids([1, 2, 3])
    r.observe_ids([1, 2, 3])  # a second mesh refresh changes nothing
    assert not r.resolved
    assert r.candidates == {SMALL, BIG}


def test_status_ids_before_mesh_info_also_count(reg):
    r = HomeResolver(reg, "192.0.2.77")
    assert r.observe_ids([3]) is None  # e.g. a 0x83 status before any mesh info
    assert r.candidates == {SMALL, BIG, ODD}
    assert r.observe_bridge(1, 53) is None
    assert r.observe_ids([4]) is None  # only House has 4: not enough on its own
    assert r.observe_ids([2, 5, 6]).home_id == BIG  # the 3 from the status still counts


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


def test_ambiguity_message_tells_user_what_to_do(reg):
    r = HomeResolver(reg, "192.0.2.77")
    r.observe_queue_id(qid(0xDEADBEEF))
    r.observe_ids([1, 2, 3])
    msg = ambiguity_message(reg, r.candidates, r.queue_id, "192.0.2.77")
    for needle in ("Cabin", "House", "192.0.2.77", "bridges:", "docs/multi_home.md", "deadbeef"):
        assert needle in msg, needle
    assert "Shed" not in msg


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


# ---- stale config: the fingerprint must not let one id decide (all data fake)
# the nested layout of a real 4-home account: ids 1..N in every home, so 1-6 are in every home and only 37-51 are
# unique (to the 51-device home)
NESTED = {"Twelve": (2001, 12), "FiftyOne": (2002, 51), "ThirtySix": (2003, 36), "Six": (2004, 6)}
TWELVE, FIFTY_ONE, THIRTY_SIX, SIX = 2001, 2002, 2003, 2004


@pytest.fixture
def nested():
    return build_nodes({"exported_homes": {
        name: {"id": hid, "access_key": 1, "devices": {i: dev(i) for i in range(1, n + 1)}}
        for name, (hid, n) in NESTED.items()
    }})


def mesh_sequence(r, ids, bridge_type=53):
    """What a session feeds the resolver for one full mesh-info sequence: the bridge record first, then the rest."""
    ids = list(ids)
    match = r.observe_bridge(ids[0], bridge_type)
    return match or r.observe_ids(ids)


def test_device_added_after_the_export_does_not_send_the_bridge_to_a_bigger_home(nested):
    """
    The user adds a bulb to the 36-device home after exporting; the mesh gives it id 37, which the config only has in
    the 51-device home. A bridge of the 36-device home reports 1-37. That must NOT resolve to the 51-device home: it has
    14 configured devices (38-51) the bridge never reported, more than the one id (37) the 36-device home lacks.
    """
    r = HomeResolver(nested, "192.0.2.77")
    assert mesh_sequence(r, range(1, 38)) is None
    assert not r.resolved
    assert THIRTY_SIX in r.candidates and FIFTY_ONE in r.candidates
    assert TWELVE not in r.candidates and SIX not in r.candidates
    # the 90 s refresh repeats the same ids: still nothing
    assert mesh_sequence(r, range(1, 38)) is None and not r.resolved


def test_a_contradicting_id_never_removes_a_home_for_good(nested):
    """A stale id 7 in the 6-device home: the 6-device home stays a candidate, so the warning names the right home."""
    r = HomeResolver(nested, "192.0.2.77")
    assert mesh_sequence(r, range(1, 8)) is None
    assert SIX in r.candidates
    assert r.candidates == {TWELVE, FIFTY_ONE, THIRTY_SIX, SIX}
    msg = ambiguity_message(nested, r.candidates, r.queue_id, "192.0.2.77")
    assert "'Six' (2004)" in msg and "export" in msg.lower()


def test_one_unique_id_is_not_enough_on_its_own(nested):
    r = HomeResolver(nested, "192.0.2.77")
    assert r.observe_ids([44]) is None  # e.g. a 0x83 status: 44 only exists in the 51-device home
    assert not r.resolved and THIRTY_SIX in r.candidates


def test_a_full_report_of_the_biggest_home_resolves_by_fingerprint(nested):
    r = HomeResolver(nested, "192.0.2.77")
    match = mesh_sequence(r, range(1, 52))
    assert match is not None and match.home_id == FIFTY_ONE and match.method == "fingerprint"
    # the detail says what decided it, so a wrong match can be spotted in the log
    assert "'ThirtySix' (2003)" in match.detail and "37-51" in match.detail


def test_the_biggest_home_with_a_few_devices_offline_still_resolves(nested):
    r = HomeResolver(nested, "192.0.2.77")
    reported = [i for i in range(1, 52) if i not in (40, 45, 50)]  # 3 silent, 12 of 37-51 reported
    match = mesh_sequence(r, reported)
    assert match is not None and match.home_id == FIFTY_ONE


def test_fully_reported_home_beats_a_home_that_lacks_one_reported_id():
    reg = build_nodes({"exported_homes": {
        "Cabin": {"id": SMALL, "devices": {i: dev(i) for i in range(1, 4)}},
        "House": {"id": BIG, "devices": {i: dev(i) for i in range(1, 5)}},
    }})
    r = HomeResolver(reg, "192.0.2.77")
    assert mesh_sequence(r, [1, 2, 3, 4]).home_id == BIG


def test_stale_small_home_bridge_is_not_resolved_into_the_bigger_home():
    """Cabin has 1-3 in the config, a 4th Cabin bulb was added later (mesh id 4); House has 1-6."""
    reg = build_nodes({"exported_homes": {
        "Cabin": {"id": SMALL, "devices": {i: dev(i) for i in range(1, 4)}},
        "House": {"id": BIG, "devices": {i: dev(i) for i in range(1, 7)}},
    }})
    r = HomeResolver(reg, "192.0.2.77")
    assert mesh_sequence(r, [1, 2, 3, 4]) is None
    assert r.candidates == {SMALL, BIG}


def test_bridge_type_unknown_in_the_config_does_not_drop_that_home():
    """Cabin-1 has no type in the config: only a known, different type is evidence against a home."""
    reg = build_nodes({"exported_homes": {
        "Cabin": {"id": SMALL, "devices": {1: dev(1, dtype=None), 2: dev(2)}},
        "House": {"id": BIG, "devices": {1: dev(1, dtype=137), 2: dev(2)}},
    }})
    assert reg.get_device(SMALL, 1).type is None
    r = HomeResolver(reg, "192.0.2.77")
    assert r.observe_bridge(1, 137) is None
    assert r.candidates == {SMALL, BIG}


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


def test_ambiguity_message_when_no_home_fits(reg):
    """Ids that no single home has (e.g. devices added after the export): the WARNING must not say they 'fit'."""
    r = HomeResolver(reg, "192.0.2.78")
    r.observe_ids([3, 6, 40])  # 3: Cabin and House, 6: House only, 40: Shed only -> no home has all three
    assert not any(f.fits for f in r.fits.values())
    msg = ambiguity_message(reg, r.candidates, r.queue_id, "192.0.2.78", none_fit=True)
    assert "fit several homes" not in msg
    assert "no single home" in msg and "re-export" in msg
