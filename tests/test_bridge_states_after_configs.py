"""After an HA restart the bridge entities are created from the configs create_bridge_device() publishes. Its state messages
are not retained, so they must come after a pause, or HA has not subscribed yet and the bridge sensors stay "unknown" (#49)."""
from types import SimpleNamespace

from cync_lan import mqtt_client as m


async def test_bridge_states_follow_its_configs_after_a_pause(monkeypatch):
    log = []
    m.MQTTClient._instance = None
    m.g.ncync_server = SimpleNamespace(running=True, node_devices={}, tcp_connections={})
    m.g.export_server = SimpleNamespace(running=True)
    m.g.uuid = "test-uuid"
    m.g.env = SimpleNamespace(app_mitm_logging=False)
    c = m.MQTTClient()

    async def pub_json(topic, *a, **k):
        log.append(("config", topic))
        return True

    async def pub(topic, *a, **k):
        log.append(("state", topic))
        return True

    async def sleep(secs):
        log.append(("sleep", secs))

    c.publish_json_msg = pub_json
    c.publish = pub
    monkeypatch.setattr(m.asyncio, "sleep", sleep)

    await c.create_bridge_device()

    last_config = max(i for i, (kind, _) in enumerate(log) if kind == "config")
    states = [i for i, (kind, _) in enumerate(log) if kind == "state"]
    assert states, "the bridge published no availability/state"
    assert min(states) > last_config, "a state went out before the last config"
    pauses = [v for kind, v in log[last_config:min(states)] if kind == "sleep"]
    assert pauses and max(pauses) >= 2, "no pause between the configs and the states"
    # these two were only published elsewhere (MQTT session start / a Cync app connecting), so an HA restart left them unknown
    sent = {topic for kind, topic in log if kind == "state"}
    assert f"{c.topic}/status/bridge/mqtt_client/connected" in sent
    assert f"{c.topic}/status/bridge/apps/connected" in sent
