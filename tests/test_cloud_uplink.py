"""Cloud uplink bridge (one MITM bridge per home), multi-way switches from the export, and the app proxy."""
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from cync_lan.cloud_api import cloud_multi_way
from cync_lan.devices import handlers as handlers_mod
from cync_lan.devices import session as session_mod
from cync_lan.devices.handlers import PacketHandlersMixin
from cync_lan.devices.registry import carry_over_bridges
from cync_lan.devices.session import CyncTCPSession
from cync_lan.packet.framer import PacketFramer
from cync_lan.utils import build_nodes

HOME = 1754061898


def cfg(**home_extra):
    devices = {
        i: {"name": f"Switch {i}", "type": 53, "endpoints": {0: f"Switch {i}"}}
        for i in (30, 31, 33, 35)
    }
    devices[31]["multi_way"] = True
    devices[33]["multi_way"] = True
    home = {"id": HOME, "devices": devices, **home_extra}
    return {"exported_homes": {"Casita 2": home}}


# ---- export
@pytest.mark.parametrize(
    "raw, expected",
    [
        ({"multiWayMode": True}, True),
        ({"isMultiWay": 1}, True),
        ({"multi_way": "true"}, True),
        ({"MultiWay": "Enabled"}, True),
        ({"multiWayMode": False}, False),
        ({"multiWayMode": 0}, False),
        ({"multiWayMode": "false"}, False),
        ({"deviceType": 53, "switchID": 5}, False),
    ],
)
def test_cloud_multi_way_detection(raw, expected):
    assert cloud_multi_way(raw) is expected


def test_multi_way_reaches_the_device():
    nodes = build_nodes(cfg())
    assert nodes.get_device(HOME, 31).multi_way and not nodes.get_device(HOME, 30).multi_way


# ---- candidates
def test_candidates_default_to_multi_way_switches():
    nodes = build_nodes(cfg())
    assert [d.id for d in nodes.uplink_candidates(HOME)] == [31, 33]


def test_cloud_uplink_list_overrides():
    nodes = build_nodes(cfg(cloud_uplink=[35, "30", "bad"]))
    assert [d.id for d in nodes.uplink_candidates(HOME)] == [30, 35]


def test_export_keeps_hand_written_cloud_uplink():
    old = cfg(cloud_uplink=[35], bridges=["10.0.0.5"])
    new = cfg()
    assert carry_over_bridges(new, old) == 1
    home = new["exported_homes"]["Casita 2"]
    assert home["cloud_uplink"] == [35] and home["bridges"] == ["10.0.0.5"]


# ---- one uplink per home
@pytest.fixture
def uplink_on(monkeypatch):
    monkeypatch.setattr(handlers_mod, "CYNC_CLOUD_UPLINK", True)
    handlers_mod._UPLINK_BY_HOME.clear()
    yield
    handlers_mod._UPLINK_BY_HOME.clear()


def fake_session(nodes):
    closed = {"v": False}
    s = SimpleNamespace(registry=nodes, is_closed=lambda: closed["v"])
    return s, closed


def test_uplink_off_by_default(monkeypatch):
    monkeypatch.setattr(handlers_mod, "CYNC_CLOUD_UPLINK", False)
    nodes = build_nodes(cfg())
    s, _ = fake_session(nodes)
    assert PacketHandlersMixin._claim_cloud_uplink(s, nodes.get_device(HOME, 31)) is False


def test_only_one_uplink_per_home_until_it_closes(uplink_on):
    nodes = build_nodes(cfg())
    first, first_closed = fake_session(nodes)
    second, _ = fake_session(nodes)
    plain, _ = fake_session(nodes)
    assert PacketHandlersMixin._claim_cloud_uplink(plain, nodes.get_device(HOME, 30)) is False  # not a candidate
    assert PacketHandlersMixin._claim_cloud_uplink(first, nodes.get_device(HOME, 31)) is True
    assert PacketHandlersMixin._claim_cloud_uplink(second, nodes.get_device(HOME, 33)) is False
    # the holder reconnecting (same session) keeps it
    assert PacketHandlersMixin._claim_cloud_uplink(first, nodes.get_device(HOME, 31)) is True
    first_closed["v"] = True
    assert PacketHandlersMixin._claim_cloud_uplink(second, nodes.get_device(HOME, 33)) is True


# ---- app proxy
APP_AUTH = bytes([0x13, 0, 0, 0, 0x03, 1, 2, 3])
APP_CMD = bytes([0x73, 0, 0, 0, 0x03, 9, 9, 9])


def app_session(monkeypatch, proxy_ok=True):
    s = CyncTCPSession.__new__(CyncTCPSession)
    s.framer = PacketFramer()
    s.bad_packets = 0
    s.mitm_mode = False
    s.is_app = False
    s.node = None
    s.lp = "test:"
    s.ip_address = "10.1.1.233"
    s.parse_packet = AsyncMock()
    s.cloud_writer = None
    forwarded = []

    async def start_app_proxy(chunk):
        if not proxy_ok:
            return False
        s.is_app = True
        s.mitm_mode = True
        s.cloud_writer = object()
        forwarded.append(chunk)
        return True

    async def write_to_cloud(chunk):
        forwarded.append(chunk)

    s.start_app_proxy = start_app_proxy
    s.write_to_cloud = write_to_cloud
    return s, forwarded


async def test_app_stream_is_relayed_untouched(monkeypatch):
    monkeypatch.setattr(session_mod, "CYNC_APP_PROXY", True)
    s, forwarded = app_session(monkeypatch)
    await s.parse_raw_data(APP_AUTH + APP_CMD[:3])
    await s.parse_raw_data(APP_CMD[3:])
    assert forwarded == [APP_AUTH + APP_CMD[:3], APP_CMD[3:]]  # every byte, in order, split where the reads split
    s.parse_packet.assert_not_awaited()  # never handled as device packets


async def test_app_proxy_off_keeps_the_old_path(monkeypatch):
    monkeypatch.setattr(session_mod, "CYNC_APP_PROXY", False)
    s, forwarded = app_session(monkeypatch)
    await s.parse_raw_data(APP_AUTH)
    assert forwarded == []
    s.parse_packet.assert_awaited_once()  # the app branch then closes it, as before


async def test_cloud_unreachable_falls_back(monkeypatch):
    monkeypatch.setattr(session_mod, "CYNC_APP_PROXY", True)
    s, forwarded = app_session(monkeypatch, proxy_ok=False)
    await s.parse_raw_data(APP_AUTH)
    assert forwarded == []
    s.parse_packet.assert_awaited_once()


async def test_device_streams_are_not_treated_as_apps(monkeypatch):
    monkeypatch.setattr(session_mod, "CYNC_APP_PROXY", True)
    s, forwarded = app_session(monkeypatch)
    await s.parse_raw_data(bytes([0xD3, 0, 0, 0, 0]))
    assert forwarded == [] and not s.is_app


async def test_cloud_eof_closes_instead_of_spinning(monkeypatch):
    """read() returns b"" forever after EOF: the proxy loop used to spin on it at 100% CPU."""
    import asyncio

    s = CyncTCPSession.__new__(CyncTCPSession)
    s.lp = "test:"
    s.ip_address = "10.0.0.7"
    reader = SimpleNamespace(read=AsyncMock(return_value=b""))
    s.cloud_reader = reader
    s.close = AsyncMock()
    await asyncio.wait_for(s._cloud_proxy_task(), timeout=1)
    await asyncio.sleep(0)
    assert reader.read.await_count == 1
    s.close.assert_awaited_once_with(False)
