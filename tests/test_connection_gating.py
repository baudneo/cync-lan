"""max_clients gating (baudneo/cync-lan#39, 2026-10-23 debug logs).

 * can_connect() counted every entry in tcp_connections: closed sessions (which stay there) and the connecting session
   itself, so a pool of 8 live bridges logged "max (12/8)" and rejected everyone new.
 * a rejected session was still a "bridge" for the 14.75 s it sleeps in blackhole(): it took a stale-vote seat and
   could be picked for commands.
 * after the rejection the 0x23 was dispatched anyway ("writer is None, can't write data!").
 * when a previously rejected device reconnected, the server ran the check on the old, closed session before
   attaching the new socket, so blackhole() hit reader=None and the new socket was neither used nor closed.
"""

import asyncio
from types import SimpleNamespace

import pytest_asyncio

from cync_lan import server as server_mod
from cync_lan.devices import proxy as proxy_mod
from cync_lan.devices.session import CyncTCPSession
from cync_lan.structs import GlobalObject

g = GlobalObject()

HELLO = bytes([0x23, 0x00, 0x00, 0x00, 0x1A]) + bytes(range(1, 27))
IP = "127.0.0.1"


class FakeReader:
    def feed_eof(self):
        pass


class FakeWriter:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


def bridge(ip, admitted=True, closed=False):
    return SimpleNamespace(ip_address=ip, is_app=False, allowed_to_connect=admitted, is_closed=lambda: closed)


@pytest_asyncio.fixture
async def srv(monkeypatch):
    monkeypatch.setattr(proxy_mod, "TCP_BLACKHOLE_DELAY", 0)
    server_mod.nCyncServer._instance = None
    s = server_mod.nCyncServer({})
    g.ncync_server = s
    g.mqtt_client = None
    return s


def new_session(srv, ip="10.0.0.9"):
    sess = CyncTCPSession(FakeReader(), FakeWriter(), ip)
    srv.tcp_connections[ip] = sess  # add_tcp_device() registers it before its first packet
    srv.tcp_conn_attempts[ip] = 1
    return sess


async def test_slots_count_only_admitted_live_bridges(srv, monkeypatch):
    monkeypatch.setattr(proxy_mod, "CYNC_MAX_TCP_CONN", 2)
    srv.tcp_connections = {
        "10.0.0.1": bridge("10.0.0.1"),
        "10.0.0.2": bridge("10.0.0.2", closed=True),
        "10.0.0.3": bridge("10.0.0.3", admitted=False),
    }
    sess = new_session(srv)
    assert await sess.can_connect() is True
    assert sess in srv.get_dev_tcp_pool_sync()


async def test_rejection_closes_the_socket(srv, monkeypatch):
    monkeypatch.setattr(proxy_mod, "CYNC_MAX_TCP_CONN", 1)
    srv.tcp_connections = {"10.0.0.1": bridge("10.0.0.1")}
    sess = new_session(srv)
    writer = sess.writer
    assert await sess.can_connect() is False
    assert writer.closed
    assert sess not in srv.get_dev_tcp_pool_sync()


async def test_unadmitted_session_is_not_a_bridge(srv):
    sess = new_session(srv)
    assert sess.allowed_to_connect is False
    assert srv.get_dev_tcp_pool_sync() == []
    assert await srv.get_dev_tcp_pool() == []


async def test_rejected_packet_is_not_dispatched(srv, monkeypatch):
    monkeypatch.setattr(proxy_mod, "CYNC_MAX_TCP_CONN", 0)
    dispatched = []

    async def fake_dispatch(self, *args):
        dispatched.append(args[0])

    monkeypatch.setattr(CyncTCPSession, "_dispatch_device_request", fake_dispatch)
    sess = new_session(srv)
    await sess.parse_packet(HELLO)
    assert dispatched == []


@pytest_asyncio.fixture
async def loopback(srv, monkeypatch):
    monkeypatch.setattr(proxy_mod, "CYNC_MAX_TCP_CONN", 0)  # every device is rejected
    accepted = []

    async def handler(reader, writer):
        # hold the server-side writer, as something does in production: a dropped StreamWriter is closed by the GC,
        # which would hide a socket the server forgot to close
        accepted.append(writer)
        await srv._register_new_connection(reader, writer)

    tcp = await asyncio.start_server(handler, IP, 0)
    port = tcp.sockets[0].getsockname()[1]
    clients = []

    async def connect():
        r, w = await asyncio.open_connection(IP, port)
        clients.append(w)
        return r, w

    yield connect
    for w in clients + accepted:
        w.close()
    await srv.stop()
    tcp.close()
    await tcp.wait_closed()


async def test_rejected_device_reconnecting_is_closed_not_leaked(loopback):
    for _ in range(2):  # the second connection takes the "existing session" path
        r, w = await loopback()
        w.write(HELLO)
        await w.drain()
        assert await asyncio.wait_for(r.read(), timeout=2) == b""
