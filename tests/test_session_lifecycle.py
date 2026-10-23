"""Session lifecycle over real loopback sockets: device drops, same-IP reconnect, shutdown under traffic."""

import asyncio

import pytest_asyncio

from cync_lan import server as server_mod
from cync_lan.devices.session import CyncTCPSession
from cync_lan.structs import GlobalObject

g = GlobalObject()

PING = bytes.fromhex("d3 00 00 00 00")
IP = "127.0.0.1"


async def until(cond, timeout=2.0):
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if cond():
            return True
        await asyncio.sleep(0.01)
    return cond()


@pytest_asyncio.fixture
async def env(monkeypatch):
    seen: list[bytes] = []

    async def fake_parse_packet(self, data):
        seen.append(data)

    monkeypatch.setattr(CyncTCPSession, "parse_packet", fake_parse_packet)
    server_mod.nCyncServer._instance = None
    srv = server_mod.nCyncServer({})
    g.ncync_server = srv
    g.mqtt_client = None
    tcp = await asyncio.start_server(srv._register_new_connection, IP, 0)
    port = tcp.sockets[0].getsockname()[1]
    clients = []

    async def connect():
        r, w = await asyncio.open_connection(IP, port)
        clients.append(w)
        return r, w

    yield srv, connect, seen
    for w in clients:
        w.close()
    await srv.stop()
    tcp.close()
    await tcp.wait_closed()


async def session_up(srv):
    assert await until(lambda: IP in srv.tcp_connections and srv.tcp_connections[IP].tasks.receive)
    return srv.tcp_connections[IP]


async def test_packets_split_and_coalesced_reach_parser(env):
    srv, connect, seen = env
    _, w = await connect()
    await session_up(srv)
    w.write(PING[:2])
    await w.drain()
    await asyncio.sleep(0.05)
    w.write(PING[2:] + PING)  # rest of the first + a whole second one
    await w.drain()
    assert await until(lambda: len(seen) == 2)
    assert seen == [PING, PING]


async def test_device_hangup_closes_session_and_tasks(env):
    srv, connect, _ = env
    _, w = await connect()
    sess = await session_up(srv)
    w.close()
    assert await until(lambda: sess._closed)
    assert sess.reader is None and sess.writer is None
    assert await until(lambda: sess.tasks.receive is None)


async def test_close_is_idempotent_and_concurrent_safe(env):
    srv, connect, _ = env
    await connect()
    sess = await session_up(srv)
    await asyncio.gather(sess.close(), sess.close(), sess.close())
    await sess.close()
    assert sess._closed and not sess.closing


async def test_reconnect_from_same_ip_reuses_session_with_clean_state(env):
    srv, connect, seen = env
    _, w1 = await connect()
    sess = await session_up(srv)
    # header declares 5 payload bytes, only 1 arrives: the new PING would be swallowed as payload
    w1.write(bytes.fromhex("d3 00 00 00 05 aa"))
    await w1.drain()
    await asyncio.sleep(0.05)
    w1.close()
    assert await until(lambda: sess._closed)

    _, w2 = await connect()
    assert await until(lambda: srv.tcp_connections.get(IP) is not None and not srv.tcp_connections[IP]._closed)
    sess2 = srv.tcp_connections[IP]
    assert sess2 is sess  # object reused so `node` survives
    w2.write(PING)
    await w2.drain()
    # the stale 3 bytes must not have been glued onto the new packet
    assert await until(lambda: PING in seen)
    assert all(len(p) == 5 for p in seen)


async def test_shutdown_during_traffic_closes_everything(env):
    srv, connect, seen = env
    _, w = await connect()
    sess = await session_up(srv)

    async def flood():
        try:
            while True:
                w.write(PING * 50)
                await w.drain()
                await asyncio.sleep(0)
        except (ConnectionError, OSError):
            pass

    task = asyncio.create_task(flood())
    assert await until(lambda: len(seen) > 100)
    await asyncio.wait_for(srv.stop(), 5)
    assert sess._closed
    assert sess.tasks.receive is None
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
