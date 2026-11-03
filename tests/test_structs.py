import asyncio
import datetime

from cync_lan.structs import ComputedTokenStruct, GlobalObject, Tasks


async def _sleeper():
    await asyncio.sleep(60)


async def test_cancel_all_cancels_proxy_tasks():
    t = Tasks(proxy_task=asyncio.create_task(_sleeper()), proxy_conn_watcher=asyncio.create_task(_sleeper()))
    tasks = list(t)
    assert len(t) == 2
    await t.cancel_all()
    assert all(x.cancelled() for x in tasks)
    assert t.proxy_task is None and t.proxy_conn_watcher is None


async def test_cancel_all_skips_calling_task():
    holder = Tasks()

    async def inner():
        holder.proxy_task = asyncio.current_task()
        holder.send = asyncio.create_task(_sleeper())
        other = holder.send
        await holder.cancel_all()
        return other.cancelled()  # we reached this line: not self-cancelled

    assert await asyncio.create_task(inner()) is True


def test_token_expires_at_accepts_string_expire_in():
    tok = ComputedTokenStruct(
        access_token="a", user_id="1", expire_in="3600", refresh_token="r", authorize="x",
        issued_at=datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC),
    )
    assert tok.expires_at == datetime.datetime(2026, 1, 1, 1, tzinfo=datetime.UTC)


def test_reload_env_bad_port_and_export_default(monkeypatch):
    monkeypatch.setenv("CYNC_MQTT_PORT", "abc")
    monkeypatch.delenv("CYNC_EXPORT_HOST", raising=False)
    monkeypatch.delenv("CYNC_HASS_APP", raising=False)
    g = GlobalObject()
    g.reload_env()
    assert g.env.mqtt_port == 1883
    assert g.env.cync_export_host == "127.0.0.1"
