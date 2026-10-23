"""MQTT service must survive malformed input and failed publishes (PLAN.md M1-M4, M12, M13)."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from cync_lan import mqtt_client as m


class _Topic:
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


class _Msg:
    def __init__(self, topic, payload):
        self.topic = _Topic(topic)
        self.payload = payload


class _Node:
    def __init__(self, dev_id=46, fan=False):
        self.id = dev_id
        self.is_fan_controller = fan
        self.entities = {}
        self.calls = []

    def _rec(self, name):
        async def f(*a, **k):
            self.calls.append((name, a))
            return True

        return f

    def __getattr__(self, name):
        if name.startswith("set_"):
            return self._rec(name)
        raise AttributeError(name)


class _Server:
    def __init__(self):
        self.node_devices = {}

    async def get_dev_tcp_pool(self):
        return []


@pytest_asyncio.fixture
async def client():
    m.MQTTClient._instance = None
    m.g.ncync_server = _Server()
    m.g.env = SimpleNamespace(app_mitm_logging=False)
    c = m.MQTTClient()
    c.publish = AsyncMock(return_value=True)
    c.pub_online = AsyncMock(return_value=True)
    c.parse_entity_state = AsyncMock(return_value=True)
    c.homeassistant_discovery = AsyncMock(return_value=True)
    c.kelvin2cync = lambda k, node: k // 100
    return c


def _topic(client, dev="123-46"):
    return f"{client.topic}/set/{dev}"


# ---- pure helpers
@pytest.mark.parametrize(
    "value, expected",
    [(5, 5), ("50", 50), ("50.0", 50), (49.6, 50), (" 7 ", 7), ("abc", None), (None, None),
     (True, None), ({}, None), ("nan", None), ("inf", None), ("", None)],
)
def test_parse_int(value, expected):
    assert m.parse_int(value) == expected


def test_clamp():
    assert (m.clamp(-5, 0, 100), m.clamp(500, 0, 100), m.clamp(7, 0, 100)) == (0, 100, 7)


def test_reconnect_delay_backs_off_and_caps():
    assert [m.reconnect_delay(n, 10) for n in (1, 2, 3, 4, 5, 6, 7)] == [10, 20, 40, 60, 60, 60, 60]
    assert m.reconnect_delay(1, None) == 5 and m.reconnect_delay(1, 0) == 5
    assert m.reconnect_delay(3, 120) == 120  # never below a user-configured base


# ---- malformed payloads must not raise (they used to kill start())
@pytest.mark.parametrize(
    "payload",
    [
        b'{"brightness": null}',
        b'{"brightness": "abc"}',
        b'{"color_temp": null}',
        b'{"color": "red"}',
        b'{"color": {"r": "x", "g": null}}',
        b'{"state": "ON", "brightness": [1]}',
        b"{not json",
        b"\xff\xfe\xfd",
        b"[1,2,3]",
        b"{}",
    ],
)
async def test_bad_payloads_do_not_raise(client, payload):
    m.g.ncync_server.node_devices[46] = _Node()
    result = await client.async_parse_mqtt_msg(_Msg(_topic(client), payload))
    assert isinstance(result, bool)


async def test_values_are_clamped(client):
    node = _Node()
    m.g.ncync_server.node_devices[46] = node
    await client.async_parse_mqtt_msg(_Msg(_topic(client), b'{"brightness": 500}'))
    await client.async_parse_mqtt_msg(
        _Msg(_topic(client), b'{"color": {"r": 999, "g": -4, "b": "12.0"}}')
    )
    assert ("set_brightness", (100, None)) in node.calls
    assert ("set_rgb", (255, 0, 12)) in node.calls


async def test_commands_run_in_order(client):
    node = _Node()
    m.g.ncync_server.node_devices[46] = node
    await client.async_parse_mqtt_msg(
        _Msg(_topic(client), b'{"state": "ON", "color": {"r": 1, "g": 2, "b": 3}}')
    )
    assert [c[0] for c in node.calls] == ["set_power", "set_rgb"]


async def test_failing_command_does_not_raise_or_block_next(client):
    node = _Node()

    async def boom(*a, **k):
        raise RuntimeError("device exploded")

    node.set_power = boom
    m.g.ncync_server.node_devices[46] = node
    await client.async_parse_mqtt_msg(
        _Msg(_topic(client), b'{"state": "ON", "color": {"r": 1, "g": 2, "b": 3}}')
    )
    assert [c[0] for c in node.calls] == ["set_rgb"]


@pytest.mark.parametrize(
    "payload, expected_handled",
    [(b"50", True), (b"50.0", True), (b"abc", False), (b"-5", False), (b"101", False)],
)
async def test_fan_percentage_validation(client, payload, expected_handled):
    node = _Node(fan=True)
    m.g.ncync_server.node_devices[46] = node
    topic = f"{_topic(client)}/percentage"
    assert await client.async_parse_mqtt_msg(_Msg(topic, payload)) is expected_handled


async def test_commands_work_when_topic_env_is_empty(client, monkeypatch):
    # self.topic falls back to a default when CYNC_TOPIC is empty; dispatch must use it
    monkeypatch.setattr(m, "CYNC_TOPIC", "")
    node = _Node()
    m.g.ncync_server.node_devices[46] = node
    assert await client.async_parse_mqtt_msg(_Msg(_topic(client), b"ON")) is True


# ---- receiver loop
async def test_receiver_survives_a_bad_message(client):
    seen = []

    async def parse(msg):
        seen.append(msg.payload)
        if msg.payload == b"bad":
            raise ValueError("boom")
        return True

    async def messages():
        for p in (b"bad", b"good"):
            yield _Msg("x", p)

    client.async_parse_mqtt_msg = parse
    client.client = SimpleNamespace(messages=messages())
    await client.start_receiver_task()
    assert seen == [b"bad", b"good"]


# ---- failed publish forces a reconnect instead of silently disabling publishing
async def test_publish_failure_wakes_session_for_reconnect(client):
    client._connected = True
    client.client = SimpleNamespace(subscribe=AsyncMock())

    async def receiver():
        await asyncio.sleep(0)
        client._on_publish_failed()  # what the publish helpers call on MqttError
        await asyncio.sleep(10)

    client.start_receiver_task = receiver
    await asyncio.wait_for(client._run_session(2), timeout=2)
    assert client._connected is False
    assert client._receiver_task is None


async def test_real_cancellation_is_not_swallowed(client):
    client._connected = True
    client.client = SimpleNamespace(subscribe=AsyncMock())

    async def receiver():
        await asyncio.sleep(10)

    client.start_receiver_task = receiver
    task = asyncio.create_task(client._run_session(2))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


# ---- start() must keep retrying after any error, and stop only when cancelled
async def test_start_survives_session_errors_and_backs_off(client, monkeypatch):
    sleeps = []

    async def fake_sleep(d):
        sleeps.append(d)

    monkeypatch.setattr(m.asyncio, "sleep", fake_sleep)
    client.connect = AsyncMock(return_value=True)
    calls = {"n": 0}

    async def session(itr):
        calls["n"] += 1
        if calls["n"] <= 2:
            raise RuntimeError("not an MqttError")
        raise asyncio.CancelledError  # simulate shutdown

    client._run_session = session
    with pytest.raises(asyncio.CancelledError):
        await client.start()
    assert calls["n"] == 3
    assert len(sleeps) == 2 and sleeps[1] > sleeps[0]  # backoff grew


async def test_start_retries_when_connect_fails(client, monkeypatch):
    monkeypatch.setattr(m.asyncio, "sleep", AsyncMock())
    results = [False, False, asyncio.CancelledError()]

    async def connect():
        r = results.pop(0)
        if isinstance(r, BaseException):
            raise r
        return r

    client.connect = connect
    with pytest.raises(asyncio.CancelledError):
        await client.start()
    assert results == []


# ---- blocking startup check must not block the event loop (M10)
async def test_startup_state_check_does_not_block_loop(client):
    import time

    client._connected = True

    def slow_sync(topic, timeout):
        time.sleep(0.4)  # what the paho connect + poll loop does
        return "ON"

    client.get_startup_topic_state_sync = slow_sync
    ticks = 0

    async def ticker():
        nonlocal ticks
        while True:
            await asyncio.sleep(0.02)
            ticks += 1

    t = asyncio.create_task(ticker())
    try:
        assert await client.get_startup_topic_state("x/status/1-2/mitm") == "ON"
    finally:
        t.cancel()
    assert ticks >= 10  # the loop kept running while the check was in flight


async def test_startup_state_check_skipped_when_disconnected(client):
    client._connected = False
    client.get_startup_topic_state_sync = lambda *a: pytest.fail("must not be called")
    assert await client.get_startup_topic_state("x") is None


# ---- availability / last will (M5)
def test_last_will_goes_to_retained_bridge_availability(client):
    will = m.MQTTClient._build_will("cync_lan")
    assert will.topic == "cync_lan/availability/bridge"
    assert will.payload == b"offline"
    assert will.retain is True


def test_entities_depend_on_device_and_bridge_availability(client):
    avty = client._availability("1-46")
    assert [a["t"] for a in avty] == [
        f"{client.topic}/availability/1-46",
        f"{client.topic}/availability/bridge",
    ]
    assert all(a["pl_avail"] == "online" and a["pl_not_avail"] == "offline" for a in avty)


async def test_stop_marks_bridge_and_every_device_offline(client):
    node = _Node(46)
    node.online = True
    m.g.ncync_server.node_devices[46] = node
    client._connected = True
    client.send_will_msg = AsyncMock(return_value=True)
    client.client = SimpleNamespace(__aexit__=AsyncMock())
    client.client.__aexit__ = AsyncMock()
    await client.stop()
    published = {(c.args[0], c.args[1]) for c in client.publish.await_args_list}
    assert (f"{client.topic}/availability/bridge", b"offline") in published
    client.pub_online.assert_any_await(46, False)
    retained = [c for c in client.publish.await_args_list if c.args[0].endswith("availability/bridge")]
    assert retained and retained[0].kwargs.get("retain") is True


# --- M7 / M9: birth handler must not block the receive loop; MITM switches survive discovery replay ---

class _Sess:
    ip_address = "10.0.0.5"

    def __init__(self, closed=False):
        self._closed = closed

    def is_closed(self):
        return self._closed


class _MitmNode:
    id = 7
    name = "lamp"
    home_id = 1
    hass_id = "1-7"
    lp = "node:"

    def __init__(self, closed=False):
        self.tcp_session = _Sess(closed)


async def test_birth_message_returns_immediately(client):
    client.homeassistant_discovery = AsyncMock(return_value=True)
    started = asyncio.get_running_loop().time()
    res = await client._handle_hass_status(["x", client_status_topic()], m.CYNC_HASS_BIRTH_MSG.encode(), "lp")
    assert res.handled
    assert asyncio.get_running_loop().time() - started < 0.5
    assert client._birth_task is not None and not client._birth_task.done()
    client._birth_task.cancel()


async def test_second_birth_replaces_first(client):
    client.homeassistant_discovery = AsyncMock(return_value=True)
    args = (["x", client_status_topic()], m.CYNC_HASS_BIRTH_MSG.encode(), "lp")
    await client._handle_hass_status(*args)
    first = client._birth_task
    await client._handle_hass_status(*args)
    await asyncio.sleep(0)
    assert first.cancelled() or first.cancelling()
    client._birth_task.cancel()


async def test_reannounce_survives_publish_error(client):
    client.homeassistant_discovery = AsyncMock(side_effect=RuntimeError("boom"))
    await client._reannounce_after_birth(0)  # must not raise


async def test_mitm_buttons_replayed_after_discovery(client):
    client.publish_json_msg = AsyncMock(return_value=True)
    client._get_device_registry = lambda node: {}
    node = _MitmNode()
    await client.add_mitm_button(node)
    client.publish_json_msg.reset_mock()
    await client.republish_mitm_buttons()
    assert client.publish_json_msg.await_count == 1


async def test_mitm_buttons_dropped_when_session_closed(client):
    client.publish_json_msg = AsyncMock(return_value=True)
    client._get_device_registry = lambda node: {}
    node = _MitmNode()
    await client.add_mitm_button(node)
    node.tcp_session._closed = True
    client.publish_json_msg.reset_mock()
    await client.republish_mitm_buttons()
    assert client.publish_json_msg.await_count == 0
    assert client._mitm_nodes == {}


def client_status_topic():
    return m.CYNC_HASS_STATUS_TOPIC


# --- M8: unknown sub_id must not raise ---

class _EntNode:
    id = 3
    name = "n"
    hass_id = "1-3"
    online = False
    is_plug = False
    is_switch = False
    supports_temperature = True
    supports_rgb = True

    def __init__(self):
        self.entities = {}


async def test_updates_with_unknown_entity_do_not_raise(client):
    node = _EntNode()
    assert await client.update_entity_power(node, 1, sub_id=5) is False
    assert await client.update_brightness(node, 50) is False
    assert await client.update_temperature(node, 50, sub_id=2) is False
    assert await client.update_rgb(node, (1, 2, 3)) is False


# --- M11 / M14 ---

@pytest.mark.parametrize("v,exp", [(12345, "1.2.345"), ("00000", "Unknown"), (0, "Unknown"), (12, "1.2"), (None, "Unknown"), (123, "Unknown")])
def test_format_fw_version(v, exp):
    assert m.format_fw_version(v) == exp


async def test_spawn_tracks_and_releases_tasks(client):
    async def ok():
        return 1

    t = client._spawn(ok(), "t")
    assert t in client.tasks
    await t
    await asyncio.sleep(0)
    assert t not in client.tasks


async def test_spawn_failure_is_logged_not_raised(client, caplog):
    async def bad():
        raise RuntimeError("x")

    t = client._spawn(bad(), "bad")
    await asyncio.gather(t, return_exceptions=True)
    await asyncio.sleep(0)
    assert client.tasks == []


# --- M15: bridge entity discovery ---

async def _bridge_confs(client, fail_on=None):
    import uuid as _uuid

    m.g.uuid = _uuid.uuid4()
    m.g.export_server = None
    m.g.ncync_server.running = True
    m.g.ncync_server.tcp_connections = {}
    published = []

    async def pj(topic, conf, **kw):
        published.append((topic, conf))
        return topic != fail_on

    client.publish_json_msg = pj
    client.publish = AsyncMock(return_value=True)
    ret = await client.create_bridge_device()
    return ret, published


async def test_bridge_entities_have_unique_consistent_ids(client):
    ret, published = await _bridge_confs(client)
    assert ret is True
    assert len(published) >= 10
    object_ids = [c["object_id"] for _, c in published if "object_id" in c]
    assert len(object_ids) == len(set(object_ids)), object_ids
    unique_ids = [c["unique_id"] for _, c in published]
    assert len(unique_ids) == len(set(unique_ids))
    for topic, conf in published:
        domain = topic.split("/")[1]
        assert conf["platform"] == domain, topic
        if "default_entity_id" in conf:
            assert conf["default_entity_id"] == f"{domain}.{conf['object_id']}", topic


async def test_bridge_discovery_reports_any_failed_publish(client):
    _, published = await _bridge_confs(client)
    victim = published[3][0]
    ret, _ = await _bridge_confs(client, fail_on=victim)
    assert ret is False


# --- M6: reconnect uses a stable client id, so the old connection must be closed first ---

async def test_connect_closes_old_client_before_new_one(client, monkeypatch):
    order = []

    class FakeClient:
        def __init__(self, **kw):
            self.kw = kw
            order.append(("new", kw["identifier"]))

        async def __aenter__(self):
            order.append("enter")
            return self

        async def __aexit__(self, *a):
            order.append("exit")

    class Old:
        async def __aexit__(self, *a):
            order.append("old_exit")

    client.client = Old()
    monkeypatch.setattr(m.aiomqtt, "Client", FakeClient)
    monkeypatch.setattr(m.g, "reload_env", lambda: None)
    m.g.env = SimpleNamespace(mqtt_host="h", mqtt_port=1883, mqtt_user=None, mqtt_pass=None, app_mitm_logging=False)
    client.send_birth_msg = AsyncMock()
    client.homeassistant_discovery = AsyncMock()
    monkeypatch.setattr(m.asyncio, "sleep", AsyncMock())
    assert await client.connect() is True
    assert order[0] == "old_exit"
    assert order[1] == ("new", client.broker_client_id)


# --- broad-except narrowing ---

async def test_update_fan_speed_false_when_a_publish_raises(client):
    from cync_lan.structs import FanSpeed

    node = _EntNode()
    node.is_fan_controller = True
    calls = []

    async def pub(*a, **k):
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError("boom")
        return True

    client.pub_entity_state = pub
    assert await client.update_fan_speed(node, FanSpeed.LOW) is False


async def test_bad_json_payload_is_rejected_not_raised(client):
    for bad in (b"{not json", b"\xff\xfe"):
        assert client._queue_json_payload(_Node(), bad, None, [], "lp") is False
