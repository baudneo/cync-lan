"""Periodic mesh info re-request (baudneo/cync-lan#39).

Bridges were seen pushing 0x83 status changes (including the stale flag the offline vote needs) for cuts made within
~2.7 min of the add-on starting, and never for cuts made later, so a bulb cut at the wall later stayed "on" forever.
Mesh info is only requested on connect; CYNC_MESH_REFRESH_SECS re-requests it on a timer.
"""

import asyncio

from cync_lan.devices.session import CyncTCPSession


def make_session(monkeypatch):
    calls = []

    async def fake_ask(self):
        calls.append(self.ip_address)

    monkeypatch.setattr(CyncTCPSession, "ask_for_mesh_info", fake_ask)
    return CyncTCPSession(None, None, "10.0.0.1"), calls


async def test_refresh_disabled_by_default(monkeypatch):
    sess, _ = make_session(monkeypatch)
    sess.start_mesh_refresh(0)
    assert sess.tasks.mesh_refresh is None


async def test_refresh_repeats_until_session_closes(monkeypatch):
    sess, calls = make_session(monkeypatch)
    sess.start_mesh_refresh(0.01)
    await asyncio.sleep(0.1)
    assert len(calls) >= 3
    task = sess.tasks.mesh_refresh
    await sess.tasks.cancel_all()
    assert task.cancelled()
    n = len(calls)
    await asyncio.sleep(0.05)
    assert len(calls) == n


async def test_refresh_stops_once_closed(monkeypatch):
    sess, calls = make_session(monkeypatch)
    sess.start_mesh_refresh(0.01)
    await asyncio.sleep(0.03)
    sess.closed = True
    await asyncio.sleep(0.05)
    assert sess.tasks.mesh_refresh.done()
    n = len(calls)
    await asyncio.sleep(0.05)
    assert len(calls) == n


async def test_restart_replaces_the_old_timer(monkeypatch):
    sess, _ = make_session(monkeypatch)
    sess.start_mesh_refresh(10)
    first = sess.tasks.mesh_refresh
    sess.start_mesh_refresh(10)
    await asyncio.sleep(0)
    assert first.cancelled() or first.cancelling()
    assert sess.tasks.mesh_refresh is not first
    await sess.tasks.cancel_all()


async def test_no_refresh_in_mitm_mode(monkeypatch):
    sess, _ = make_session(monkeypatch)
    sess.mitm_mode = True
    sess.start_mesh_refresh(0.01)
    assert sess.tasks.mesh_refresh is None
