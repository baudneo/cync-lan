"""
Multi-home device registry: devices are keyed by (home_id, dev_id) because every Cync home is its
own BLE mesh and mesh ids restart at 1 in each home (so homes used to overwrite each other).
All data below is fake.
"""

import pytest

from cync_lan.devices import CyncDevice
from cync_lan.devices.registry import DeviceRegistry, HomeInfo
from cync_lan.utils import build_nodes

HOME_SMALL, HOME_BIG, HOME_ODD = 1001, 1002, 1003


def dev(dev_id, dtype=53, **kw):
    d = {"name": f"Dev {dev_id}", "type": dtype, "fw": "10209",
         "mac": f"02:00:00:00:0A:{dev_id:02X}", "wifi_mac": f"02:00:00:00:0B:{dev_id:02X}",
         "endpoints": {0: f"Dev {dev_id}"}}
    d.update(kw)
    return d


def multi_home_cfg():
    """Nested id sets like the real-world case: 1-3 within 1-6, plus a home with an id nobody else has."""
    return {
        "exported_homes": {
            "Cabin": {"id": HOME_SMALL, "access_key": 11111, "mac": "02:00:00:00:01:00",
                      "devices": {i: dev(i) for i in range(1, 4)}},
            "House": {"id": HOME_BIG, "access_key": 22222, "mac": "02:00:00:00:02:00",
                      "devices": {i: dev(i, dtype=137 if i == 2 else 53) for i in range(1, 7)}},
            "Shed": {"id": str(HOME_ODD), "access_key": 33333, "mac": "02:00:00:00:03:00",
                     "bridges": ["192.0.2.30", " 192.0.2.31 "],
                     "devices": {1: dev(1, switch_id=555001), 40: dev(40, dtype=68)}},
            "Empty": {"id": 1004, "access_key": 44444, "mac": "02:00:00:00:04:00", "devices": {}},
        }
    }


@pytest.fixture
def reg():
    return build_nodes(multi_home_cfg())


def test_build_nodes_returns_registry_keyed_by_home_and_id(reg):
    assert isinstance(reg, DeviceRegistry)
    assert len(reg) == 3 + 6 + 2  # nothing overwritten
    assert all(isinstance(k, tuple) and len(k) == 2 for k in reg)
    assert (HOME_SMALL, 1) in reg and (HOME_BIG, 1) in reg and (HOME_ODD, 1) in reg
    assert len(list(reg.values())) == len(reg)


def test_same_id_in_each_home_is_a_distinct_device(reg):
    small, big, odd = (reg.get_device(h, 1) for h in (HOME_SMALL, HOME_BIG, HOME_ODD))
    assert len({id(small), id(big), id(odd)}) == 3
    assert (small.home_id, big.home_id, odd.home_id) == (HOME_SMALL, HOME_BIG, HOME_ODD)
    assert small.key == (HOME_SMALL, 1) and odd.key == (HOME_ODD, 1)
    assert small.id == big.id == odd.id == 1  # per-home mesh id, used as the control packet target
    assert reg[(HOME_BIG, 1)] is big


def test_home_id_is_coerced_to_int_and_existing_ids_unchanged(reg):
    odd = reg.get_device(HOME_ODD, 40)
    assert odd.home_id == HOME_ODD and isinstance(odd.home_id, int)
    # HA unique ids / topics embed the home id: these strings must not change
    assert odd.hass_id == f"{HOME_ODD}-40"


def test_device_carries_home_name(reg):
    assert reg.get_device(HOME_BIG, 6).home_name == "House"
    assert reg.home_name(HOME_SMALL) == "Cabin"
    assert reg.home_name(9999) is None


def test_get_device_missing(reg):
    assert reg.get_device(HOME_SMALL, 6) is None
    assert reg.get_device(9999, 1) is None


def test_in_home_and_home_ids(reg):
    assert [d.id for d in reg.in_home(HOME_BIG)] == [1, 2, 3, 4, 5, 6]
    assert [d.id for d in reg.in_home(HOME_ODD)] == [1, 40]
    assert reg.in_home(9999) == []
    # a home without devices cannot have a bridge, it is not registered
    assert reg.home_ids() == [HOME_SMALL, HOME_BIG, HOME_ODD]


def test_homes_with_nested_ids(reg):
    assert reg.homes_with(1) == {HOME_SMALL, HOME_BIG, HOME_ODD}
    assert reg.homes_with(3) == {HOME_SMALL, HOME_BIG}
    assert reg.homes_with(5) == {HOME_BIG}
    assert reg.homes_with(40) == {HOME_ODD}
    assert reg.homes_with(99) == set()


def test_home_metadata(reg):
    info = reg.home(HOME_ODD)
    assert isinstance(info, HomeInfo)
    assert info.home_id == HOME_ODD and info.name == "Shed"
    assert info.bridges == frozenset({"192.0.2.30", "192.0.2.31"})  # whitespace stripped
    assert reg.home(HOME_SMALL).bridges == frozenset()
    assert reg.home_switch_ids(HOME_ODD) == {555001: reg.get_device(HOME_ODD, 1)}
    assert reg.home_switch_ids(HOME_BIG) == {}
    assert reg.homes_for_bridge_ip("192.0.2.31") == {HOME_ODD}
    assert reg.homes_for_bridge_ip("192.0.2.99") == set()


def test_switch_id_config_field(reg):
    assert reg.get_device(HOME_ODD, 1).switch_id == 555001
    assert reg.get_device(HOME_ODD, 40).switch_id is None


@pytest.mark.parametrize("bad", [0, "abc", None, -5, [1]])
def test_bad_switch_id_is_ignored_device_kept(bad):
    cfg = multi_home_cfg()
    cfg["exported_homes"]["Shed"]["devices"][1]["switch_id"] = bad
    reg = build_nodes(cfg)
    assert reg.get_device(HOME_ODD, 1).switch_id is None


def test_quoted_switch_id_is_coerced():
    cfg = multi_home_cfg()
    cfg["exported_homes"]["Shed"]["devices"][1]["switch_id"] = "555001"
    assert build_nodes(cfg).get_device(HOME_ODD, 1).switch_id == 555001


@pytest.mark.parametrize("bad_id", ["abc", "12ab", None, True, 1.5, [1]])
def test_non_numeric_home_id_skips_only_that_home(bad_id, caplog):
    cfg = multi_home_cfg()
    cfg["exported_homes"]["Cabin"]["id"] = bad_id
    reg = build_nodes(cfg)
    assert HOME_SMALL not in reg.home_ids()
    assert reg.home_ids() == [HOME_BIG, HOME_ODD]
    assert "Cabin" in caplog.text


def test_duplicate_home_id_skips_the_second_home(caplog):
    cfg = multi_home_cfg()
    cfg["exported_homes"]["Shed"]["id"] = HOME_BIG
    reg = build_nodes(cfg)
    assert reg.home_ids() == [HOME_SMALL, HOME_BIG]
    assert reg.home_name(HOME_BIG) == "House" and len(reg.in_home(HOME_BIG)) == 6
    assert "Shed" in caplog.text


@pytest.mark.parametrize("bad", ["192.0.2.30", {"a": 1}, 7])
def test_bridges_must_be_a_list_home_still_loads(bad, caplog):
    cfg = multi_home_cfg()
    cfg["exported_homes"]["Shed"]["bridges"] = bad
    reg = build_nodes(cfg)
    assert reg.home(HOME_ODD).bridges == frozenset()
    assert len(reg.in_home(HOME_ODD)) == 2
    assert "bridges" in caplog.text


def test_bad_bridge_entries_are_dropped_good_ones_kept(caplog):
    cfg = multi_home_cfg()
    cfg["exported_homes"]["Shed"]["bridges"] = ["192.0.2.30", "not-an-ip", 12, None, "2001:db8::1"]
    reg = build_nodes(cfg)
    assert reg.home(HOME_ODD).bridges == frozenset({"192.0.2.30", "2001:db8::1"})
    assert "not-an-ip" in caplog.text


def test_bridge_ip_listed_in_two_homes_is_reported(caplog):
    cfg = multi_home_cfg()
    cfg["exported_homes"]["Cabin"]["bridges"] = ["192.0.2.30"]
    reg = build_nodes(cfg)
    assert reg.homes_for_bridge_ip("192.0.2.30") == {HOME_SMALL, HOME_ODD}
    assert "192.0.2.30" in caplog.text


def test_registry_add_and_direct_use():
    r = DeviceRegistry()
    r.add_home(7, "Seven", bridges=["192.0.2.7"])
    a = CyncDevice(dev_id=1, home_id=7, name="a")
    b = CyncDevice(dev_id=1, home_id=8, name="b", home_name="Eight")
    r.add(a)
    r.add(b)
    assert r.get_device(7, 1) is a and r.get_device(8, 1) is b
    assert r.home_ids() == [7, 8]
    assert r.home_name(8) == "Eight"  # home registered from the device when not added explicitly
    assert r.homes_with(1) == {7, 8}


def test_add_device_without_home_id_rejected():
    with pytest.raises(ValueError):
        DeviceRegistry().add(CyncDevice(dev_id=1))


def test_cync_device_key_without_registry():
    d = CyncDevice(dev_id=4, home_id=42)
    assert d.key == (42, 4)
    assert d.home_name is None and d.switch_id is None
