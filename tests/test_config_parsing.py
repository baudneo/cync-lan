"""One bad entry must not abort startup or the cloud export (PLAN.md items 10-11)."""

import pytest
import yaml

from cync_lan import cloud_api
from cync_lan.utils import ConfigError, build_nodes, parse_config


def good_cfg():
    return {
        "exported_homes": {
            "Home": {
                "id": 169573386,
                "devices": {
                    7: {"name": "Lamp", "type": 137, "fw": "30000", "mac": "AA:BB", "wifi_mac": "CC:DD",
                        "endpoints": {0: "Lamp"}},
                    "12": {"name": "Quoted id", "type": 137},
                    9: {"name": "Off", "enabled": False},
                    10: {"name": "Off str", "enabled": "no"},
                },
            }
        }
    }


def test_good_config():
    nodes = build_nodes(good_cfg())
    assert sorted(nodes) == [7, 12]  # disabled ones skipped, quoted id normalized to int
    assert nodes[7].name == "Lamp" and nodes[12].id == 12


def test_legacy_account_data_key_still_works():
    cfg = {"account data": good_cfg()["exported_homes"]}
    assert sorted(build_nodes(cfg)) == [7, 12]


@pytest.mark.parametrize(
    "bad_device",
    ["just a string", None, {"name": "x", "endpoints": ["not", "a", "mapping"]},
     {"name": "x", "endpoints": {"abc": "bad ep id"}}],
)
def test_one_bad_device_is_skipped_others_survive(bad_device):
    cfg = good_cfg()
    cfg["exported_homes"]["Home"]["devices"]["bad"] = bad_device
    cfg["exported_homes"]["Home"]["devices"]["notanint"] = {"name": "x"}
    assert sorted(build_nodes(cfg)) == [7, 12]


def test_bad_homes_are_skipped():
    cfg = good_cfg()
    cfg["exported_homes"]["NoId"] = {"devices": {1: {"name": "a"}}}
    cfg["exported_homes"]["NullDevices"] = {"id": 5, "devices": None}
    cfg["exported_homes"]["NotAMapping"] = "oops"
    assert sorted(build_nodes(cfg)) == [7, 12]


@pytest.mark.parametrize(
    "raw", [None, [], "text", {}, {"something": "else"}, {"exported_homes": None}, {"exported_homes": [1]}]
)
def test_unusable_file_raises_config_error(raw):
    with pytest.raises(ConfigError):
        build_nodes(raw)


async def test_parse_config_reads_file_and_reports_bad_yaml(tmp_path):
    ok = tmp_path / "ok.yaml"
    ok.write_text(yaml.dump(good_cfg()))
    assert sorted(await parse_config(ok)) == [7, 12]
    bad = tmp_path / "bad.yaml"
    bad.write_text("a: [unclosed")
    with pytest.raises(ConfigError):
        await parse_config(bad)
    empty = tmp_path / "empty.yaml"
    empty.write_text("")
    with pytest.raises(ConfigError):
        await parse_config(empty)


# ---- cloud export parsing
@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setattr(cloud_api, "CYNC_CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(cloud_api, "CYNC_EXPORT_SOURCE", "file")  # don't write raw_mesh.cync
    obj = object.__new__(cloud_api.CyncCloudAPI)
    obj.lp = "test"
    return obj


def bulb(raw_id, name="Bulb", dtype=137, **kw):
    d = {"deviceID": raw_id, "displayName": name, "mac": "AA:BB:CC", "deviceType": dtype,
         "firmwareVersion": "30000"}
    d.update(kw)
    return d


def home(*bulbs, name="Home"):
    return {"name": name, "id": 1, "product_id": "p", "access_key": "k", "mac": "m",
            "properties": {"bulbsArray": list(bulbs)}}


async def test_export_parses_devices_and_sub_devices(api):
    out = await api._parse_raw_export([
        home(bulb("169573386007", "Lamp"), bulb("169573386001007", "Outlet 1"), bulb("169573386002007", "Outlet 2")),
    ])
    devs = out["exported_homes"]["Home"]["devices"]
    assert list(devs) == [7]
    assert devs[7]["endpoints"] == {1: "Outlet 1", 2: "Outlet 2"}


async def test_export_skips_malformed_device_but_keeps_others(api):
    out = await api._parse_raw_export([
        home(
            bulb("169573386007", "Good"),
            bulb("169573386008", "Bad type", dtype="abc"),
            bulb("short", "Bad id"),
            {"displayName": "missing attrs"},
            "not even a dict",
            bulb("169573386009", "Also good"),
        )
    ])
    assert sorted(out["exported_homes"]["Home"]["devices"]) == [7, 9]


async def test_export_survives_home_property_failure(api):
    async def fail(*a):
        raise ConnectionError("cloud down")

    api.get_cync_home_properties = fail
    broken = {"name": "Broken", "id": 2, "product_id": "p"}  # no 'properties' -> must fetch
    out = await api._parse_raw_export([broken, home(bulb("169573386007"), name="Fine")])
    assert list(out["exported_homes"]) == ["Fine"]


async def test_export_cloud_error_dict_is_a_clear_error(api):
    with pytest.raises(RuntimeError, match="Access-Token expired"):
        await api._parse_raw_export({"error": {"msg": "Access-Token expired"}})


async def test_export_ignores_unusable_homes(api):
    out = await api._parse_raw_export([
        None, {"id": 1}, {"name": ""}, {"name": "NoBulbs", "id": 3, "properties": {"other": 1}},
        {"name": "PropsNotDict", "id": 4, "properties": "x"}, home(bulb("169573386007")),
    ])
    assert list(out["exported_homes"]) == ["Home"]
