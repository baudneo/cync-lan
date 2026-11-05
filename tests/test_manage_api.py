"""Web UI management API: homes / devices / Cync rooms (read only) / local groups (CRUD), written to cync_mesh.yaml."""
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import yaml
from fastapi.testclient import TestClient

from cync_lan import exporter, manage_api
from cync_lan.utils import build_nodes

HOME = 1754061898


def cfg():
    devices = {i: {"name": f"Switch {i}", "type": 53, "mac": "AA", "endpoints": {0: f"Switch {i}"}} for i in (12, 15, 28)}
    return {"exported_homes": {"Casita 2": {
        "id": HOME, "access_key": 123456, "devices": devices,
        "groups": {32776: {"name": "Master Toilet", "members": [15]}, 32789: {"name": "Master Closets", "members": [28]}},
    }}}


@pytest.fixture
def api(tmp_path, monkeypatch):
    path = tmp_path / "cync_mesh.yaml"
    path.write_text(yaml.dump(cfg()))
    monkeypatch.setattr(manage_api, "CYNC_CONFIG_FILE_PATH", str(path))
    monkeypatch.setattr(exporter, "CYNC_HASS_APP", True)  # ingress: no token
    nodes = build_nodes(cfg())
    server = SimpleNamespace(node_devices=nodes, get_dev_tcp_pool=AsyncMock(return_value=[]))
    monkeypatch.setattr(manage_api.g, "ncync_server", server)
    monkeypatch.setattr(manage_api.g, "mqtt_client", None)
    return TestClient(exporter.app), path, nodes


def saved(path):
    return yaml.safe_load(path.read_text())["exported_homes"]["Casita 2"]


def test_list_homes(api):
    client, _, _ = api
    [home] = client.get("/api/manage/homes").json()
    assert home["id"] == HOME and home["name"] == "Casita 2"
    assert [d["id"] for d in home["devices"]] == [12, 15, 28]
    assert {r["name"] for r in home["rooms"]} == {"Master Toilet", "Master Closets"}
    assert home["local_groups"] == [] and home["next_local_group_id"] == 0x80FE
    assert next(d for d in home["devices"] if d["id"] == 15)["room"] == 32776
    assert "access_key" not in str(home)  # never sent to the browser


def test_create_update_delete_local_group(api):
    client, path, nodes = api
    r = client.post(f"/api/manage/homes/{HOME}/local_groups?sync=false", json={"name": "Suite", "members": [15, 12]})
    assert r.status_code == 200 and r.json()["id"] == 0x80FE and r.json()["members"] == [12, 15]
    assert saved(path)["local_groups"] == {0x80FE: {"name": "Suite", "members": [12, 15]}}
    assert saved(path)["access_key"] == 123456  # the rest of the file is kept
    assert nodes.get_group(HOME, 0x80FE).is_local
    assert list(path.parent.glob("cync_mesh.yaml.bak-*"))  # previous file backed up

    r = client.put(f"/api/manage/homes/{HOME}/local_groups/{0x80FE}?sync=false", json={"name": "Suite 2", "members": [28]})
    assert r.json()["members"] == [28] and saved(path)["local_groups"][0x80FE]["name"] == "Suite 2"

    r = client.delete(f"/api/manage/homes/{HOME}/local_groups/{0x80FE}?remove_from_switches=false")
    assert r.status_code == 200 and "local_groups" not in saved(path)
    assert nodes.get_group(HOME, 0x80FE) is None


@pytest.mark.parametrize("body, status", [
    ({"name": "x", "members": [99]}, 400),          # not a device of the home
    ({"name": "x", "members": []}, 400),
    ({"name": "x", "members": [12], "id": 32776}, 409),  # the Cync account's room
    ({"name": "x", "members": [12], "id": 0x9000}, 400),
    ({"name": "", "members": [12]}, 422),
])
def test_bad_local_groups(api, body, status):
    client, path, _ = api
    assert client.post(f"/api/manage/homes/{HOME}/local_groups?sync=false", json=body).status_code == status
    assert "local_groups" not in saved(path)


def test_cync_rooms_are_read_only(api):
    client, _, _ = api
    assert client.delete(f"/api/manage/homes/{HOME}/local_groups/32776").status_code == 404
    assert client.post(f"/api/manage/homes/{HOME}/local_groups/32776/sync").status_code == 404


def test_rename_and_disable_device(api):
    client, path, nodes = api
    r = client.patch(f"/api/manage/homes/{HOME}/devices/12", json={"name": "Shower"})
    assert r.json() == {"id": 12, "name": "Shower", "enabled": True, "restart_required": False}
    assert saved(path)["devices"][12]["name"] == "Shower" and saved(path)["devices"][12]["endpoints"] == {0: "Shower"}
    assert nodes.get_device(HOME, 12).name == "Shower"
    r = client.patch(f"/api/manage/homes/{HOME}/devices/12", json={"enabled": False})
    assert r.json()["restart_required"] is True and saved(path)["devices"][12]["enabled"] is False


def test_unknown_home(api):
    client, _, _ = api
    assert client.post("/api/manage/homes/1/local_groups", json={"name": "x", "members": [1]}).status_code == 404


def test_needs_the_token_outside_ingress(api, monkeypatch):
    client, _, _ = api
    monkeypatch.setattr(exporter, "CYNC_HASS_APP", False)
    monkeypatch.setattr(exporter, "CYNC_EXPORT_TOKEN", "secret")
    assert client.get("/api/manage/homes").status_code == 401
    assert client.get("/api/manage/homes", headers={"Authorization": "Bearer secret"}).status_code == 200
