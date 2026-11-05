"""Hybrid relay: a device's connection goes on to the Cync cloud AND cync-lan keeps controlling it on the same socket."""
import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

from cync_lan.const import parse_hybrid_relay
from cync_lan.devices import device as device_mod
from cync_lan.devices.session import CyncTCPSession
from cync_lan.packet import PacketBuilder
from cync_lan.packet.framer import PacketFramer
from cync_lan.structs import ControlMessageCallback, MessageCache

QID = b"\x37\x64\xe6\x89"


def outer(ptype, payload, msg_id=b"\x00\x00\x00", qid=QID):
    body = qid + msg_id + payload
    return bytes([ptype, 0, 0, len(body) // 256, len(body) % 256]) + body


def control_reply(ctrl_id, op=0xD0, ok=1, msg_id=b"\x00\x05\x00"):
    # device -> server 0x73: 7E <ctrl id> 00 00 00 F9 <op> <ok> ... 7E
    return outer(0x73, bytes([0x7E, ctrl_id, 0, 0, 0, 0xF9, op, ok, 0, 0x7E]), msg_id=msg_id)


STATUS_83 = outer(0x83, bytes([0x7E, 0x30, 0, 0, 0, 0xFA, 0xDB, 0x13, 0, 0x7E]), msg_id=b"\x00\x21\x00")
PING_D3 = bytes([0xD3, 0, 0, 0, 0])


def test_parse_hybrid_relay():
    assert parse_hybrid_relay("") == frozenset()
    assert parse_hybrid_relay(" 1754061898-12, ALL ") == {"1754061898-12", "all"}


def session():
    s = CyncTCPSession.__new__(CyncTCPSession)
    s.framer = PacketFramer()
    s.bad_packets = 0
    s.mitm_mode = True
    s.hybrid = True
    s.is_app = False
    s.node = None
    s.lp = "t:"
    s.ip_address = "10.1.2.50"
    s.queue_id = QID
    s.messages = MessageCache()
    s.cloud_writer = object()
    s.parse_packet = AsyncMock()
    s.write = AsyncMock(return_value=True)
    s.sent_to_cloud = []

    async def to_cloud(pkt):
        s.sent_to_cloud.append(pkt)

    s.write_to_cloud = to_cloud
    return s


def test_own_reply_detection():
    s = session()
    s.messages.control[0x05] = object()
    assert s.is_own_reply(control_reply(0x05))
    assert not s.is_own_reply(control_reply(0x06))  # the cloud's command
    s.hybrid_sent_at = time.time()
    assert s.is_own_reply(outer(0x7B, b"", msg_id=b"\x00\x00\x00"))
    assert not s.is_own_reply(outer(0x7B, b"", msg_id=b"\x00\x05\x00"))
    s.hybrid_sent_at = time.time() - 60
    assert not s.is_own_reply(outer(0x7B, b"", msg_id=b"\x00\x00\x00"))
    assert not s.is_own_reply(STATUS_83)


async def test_device_stream_forwarded_per_packet_minus_our_replies():
    s = session()
    s.messages.control[0x05] = object()
    mine, theirs = control_reply(0x05), control_reply(0x09)
    stream = STATUS_83 + mine + theirs + PING_D3
    await s.parse_raw_data(stream[:7])  # split mid-packet: nothing is complete yet
    await s.parse_raw_data(stream[7:])
    assert s.sent_to_cloud == [STATUS_83, theirs, PING_D3]
    assert s.parse_packet.await_count == 4  # cync-lan still reads everything (state for HA)
    # our reply is acked by us (the cloud never saw it), as a 0x78 for its msg id
    s.write.assert_awaited_once_with(PacketBuilder.build_73_ack(QID, b"\x00\x05\x00"))


async def test_plain_mitm_still_forwards_raw_chunks():
    s = session()
    s.hybrid = False
    await s.parse_raw_data(STATUS_83[:7])
    assert s.sent_to_cloud == [STATUS_83[:7]]


async def test_cloud_data_reaches_the_device_as_whole_packets():
    s = session()
    s.write_lock = asyncio.Lock()
    s.mitm_logger = SimpleNamespace(debug=lambda *a, **k: None)
    s.mitm_bytes_from_cloud = 0
    written = []
    s.writer = SimpleNamespace(write=written.append, drain=AsyncMock())
    a3 = bytes([0xA3, 0, 0, 0, 7]) + b"\x43\x2f\x84\x4e\x60\xb5\x00"
    ack88 = bytes([0x88, 0, 0, 0, 3, 0, 0x0F, 0])
    chunks = [a3[:4], a3[4:] + ack88[:2], ack88[2:], b""]
    s.cloud_reader = SimpleNamespace(read=AsyncMock(side_effect=chunks))
    s.close = AsyncMock()
    await asyncio.wait_for(s._cloud_proxy_task(), 1)
    assert written == [a3, ack88]


def bridge(name, mitm=False, hybrid=False):
    return SimpleNamespace(
        name=name, ready_to_control=True, mitm_mode=mitm, hybrid=hybrid, hybrid_sent_at=0.0, queue_id=QID,
        ip_address=name, node=SimpleNamespace(id=0), messages=SimpleNamespace(control={}), write=AsyncMock(),
        get_ctrl_msg_id_bytes=lambda: [0x05],
    )


async def test_commands_go_to_hybrid_bridges_but_not_plain_mitm(monkeypatch):
    plain, hyb = bridge("mitm", mitm=True), bridge("hybrid", mitm=True, hybrid=True)
    monkeypatch.setattr(device_mod.g, "ncync_server", SimpleNamespace(get_dev_tcp_pool=AsyncMock(return_value=[plain, hyb])))
    monkeypatch.setattr(device_mod, "CYNC_CMD_BROADCASTS", 2)
    target = SimpleNamespace(id=12, tcp_session=hyb, home_id=1, home_name="H", name="shower")
    cb = ControlMessageCallback(msg_id=0, message=None, sent_at=0.0, callback=None)
    await device_mod.CyncDevice.send_command(target, 0xD0, 0x0D, 0, bytes([0x11, 0x02, 1, 0, 0]), cb, "t:")
    assert hyb.write.await_count == 1 and plain.write.await_count == 0
    assert hyb.hybrid_sent_at > 0 and 0x05 in hyb.messages.control


# ---- admission: a hybrid device always gets its own connection
async def test_hybrid_device_is_admitted_past_a_full_home(monkeypatch):
    from cync_lan import server as server_mod
    from cync_lan.devices import proxy as proxy_mod
    from cync_lan.devices.device import CyncDevice
    from cync_lan.devices.registry import DeviceRegistry
    from cync_lan.structs import GlobalObject

    g = GlobalObject()
    monkeypatch.setattr(proxy_mod, "TCP_BLACKHOLE_DELAY", 0)
    monkeypatch.setattr(proxy_mod, "CYNC_MAX_TCP_CONN", 1)
    monkeypatch.setattr(proxy_mod, "CYNC_HYBRID_RELAY", frozenset({"1754061898-12"}))
    reg = DeviceRegistry()
    reg.add_home(1754061898, "Casita 2")
    reg.add(CyncDevice(12, dev_type=53, name="Master Shower Lights", home_id=1754061898, home_name="Casita 2",
                       entities={}, switch_id=655942622))
    reg.add(CyncDevice(13, dev_type=53, name="Other", home_id=1754061898, home_name="Casita 2", entities={},
                       switch_id=111))
    server_mod.nCyncServer._instance = None
    srv = server_mod.nCyncServer(reg, home_grace_secs=0)
    g.ncync_server = srv
    g.mqtt_client = None
    full = SimpleNamespace(ip_address="10.0.0.1", is_app=False, allowed_to_connect=True, is_closed=lambda: False,
                           home_id=1754061898, hybrid=False)
    srv.tcp_connections = {"10.0.0.1": full}

    def hello(switch_id):
        return bytes([0x23, 0, 0, 0, 0x1A, 0]) + switch_id.to_bytes(4, "big") + bytes(21)

    class W:
        def close(self):
            pass

        async def wait_closed(self):
            pass

    def sess(ip):
        s = CyncTCPSession(SimpleNamespace(feed_eof=lambda: None), W(), ip, registry=reg)
        srv.tcp_connections[ip] = s
        srv.tcp_conn_attempts[ip] = 1
        return s

    assert await sess("10.0.0.9").can_connect(hello(111)) is False  # the home is full
    shower = sess("10.1.2.174")
    assert await shower.can_connect(hello(655942622)) is True  # listed in hybrid relay: admitted anyway
    # and a hybrid session does not take a slot from the others
    shower.hybrid = True
    full.allowed_to_connect = False
    assert await sess("10.0.0.8").can_connect(hello(111)) is True
