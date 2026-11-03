"""Feed a recorded capture (see cync_lan.capture) through a real CyncTCPSession and report what happened."""

import asyncio
from dataclasses import dataclass, field
from typing import List
from unittest.mock import AsyncMock

from cync_lan import server as server_mod
from cync_lan.capture import Capture
from cync_lan.devices import CyncTCPSession
from cync_lan.stats import stats
from cync_lan.structs import GlobalObject
from cync_lan.utils import build_nodes

g = GlobalObject()


class FakeWriter:
    """Stands in for the socket's StreamWriter and records everything the session sends."""

    def __init__(self):
        self.sent: List[bytes] = []
        self.closed = False

    def write(self, data):
        self.sent.append(bytes(data))

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    def is_closing(self):
        return self.closed

    async def wait_closed(self):
        pass

    def get_extra_info(self, name, default=None):
        return ("127.0.0.1", 0) if name == "peername" else default


@dataclass
class ReplayResult:
    session: CyncTCPSession
    tx: List[bytes] = field(default_factory=list)
    packets_failed: int = 0
    dropped_bytes: int = 0
    pending: int = 0
    packets_received: int = 0


def nodes_from_info(info: dict) -> dict:
    """Rebuild the configured devices from the ids/types a capture recorded (names are made up)."""
    devices = {}
    for node_id, spec in (info.get("nodes") or {}).items():
        if isinstance(spec, int):  # tolerate the old {id: type} shape
            spec = {"type": spec, "endpoints": []}
        devices[int(node_id)] = {
            "name": f"node{node_id}",
            "type": spec.get("type"),
            "endpoints": {int(e): f"node{node_id}-ep{e}" for e in spec.get("endpoints", [])},
        }
    return build_nodes({"exported_homes": {"Replay": {"id": 1, "devices": devices}}}) if devices else {}


async def replay(cap: Capture, ip: str = "127.0.0.1") -> ReplayResult:
    """Run every recorded rx chunk, in order and with its original boundaries, through a fresh session."""
    stats.reset()
    saved = (g.ncync_server, g.mqtt_client)
    server_mod.nCyncServer._instance = None
    server = server_mod.nCyncServer(nodes_from_info(cap.info))
    g.ncync_server = server
    g.mqtt_client = AsyncMock()
    g.mqtt_client.get_startup_topic_state.return_value = None
    g.mqtt_client.topic = "replay"
    writer = FakeWriter()
    session = CyncTCPSession(asyncio.StreamReader(), writer, ip)
    server.tcp_connections[ip] = session
    server.tcp_conn_attempts[ip] = 1  # _register_new_connection does this before creating a session
    try:
        for _t, kind, data in cap.records:
            if kind == "rx":
                await session.parse_raw_data(data)
                await asyncio.sleep(0)  # let spawned handler tasks run
        await asyncio.sleep(0.05)
        result = ReplayResult(
            session=session,
            tx=list(writer.sent),
            packets_failed=stats.get("packets_failed"),
            dropped_bytes=session.framer.dropped_bytes,
            pending=session.framer.pending,
            packets_received=stats.get("packets_received"),
        )
    finally:
        await session.close()
        g.ncync_server, g.mqtt_client = saved
    return result
