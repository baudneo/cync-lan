import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from cync_lan import mqtt_client as mqtt_mod


class _MsgTopic:
    def __init__(self, value: str):
        self.value = value

    def __str__(self):
        return self.value


class _Msg:
    def __init__(self, topic: str, payload: bytes):
        self.topic = _MsgTopic(topic)
        self.payload = payload


class _DummyServer:
    def __init__(self):
        self.node_devices = {}

    async def get_dev_tcp_pool(self):
        return []


class _DummyNode:
    def __init__(self, dev_id: int = 46):
        self.id = dev_id
        self.is_fan_controller = False
        self.entities = {}

    async def set_power(self, *_args, **_kwargs):
        return True

    async def set_brightness(self, *_args, **_kwargs):
        return True

    async def set_temperature(self, *_args, **_kwargs):
        return True

    async def set_rgb(self, *_args, **_kwargs):
        return True

    async def set_lightshow(self, *_args, **_kwargs):
        return True


class TestMQTTMessageParsing(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        mqtt_mod.MQTTClient._instance = None
        mqtt_mod.g.ncync_server = _DummyServer()
        mqtt_mod.g.env = SimpleNamespace(app_mitm_logging=False)

        self.client = mqtt_mod.MQTTClient()
        self.client.publish = AsyncMock(return_value=True)
        self.client.homeassistant_discovery = AsyncMock(return_value=True)
        self.client.pub_online = AsyncMock(return_value=True)
        self.client.parse_entity_state = AsyncMock(return_value=True)

    async def test_bridge_export_start_strict_topic_is_handled(self):
        msg = _Msg(f"{mqtt_mod.CYNC_TOPIC}/set/bridge/export/start", b"press")
        result = await self.client.async_parse_mqtt_msg(msg)
        self.assertIsInstance(result, bool)
        self.assertTrue(result)

    async def test_bridge_start_export_legacy_topic_not_handled(self):
        msg = _Msg(f"{mqtt_mod.CYNC_TOPIC}/set/bridge/start_export", b"press")
        result = await self.client.async_parse_mqtt_msg(msg)
        self.assertIsInstance(result, bool)
        self.assertFalse(result)

    async def test_non_json_on_payload_is_handled(self):
        node = _DummyNode(dev_id=46)
        mqtt_mod.g.ncync_server.node_devices[46] = node
        msg = _Msg(f"{mqtt_mod.CYNC_TOPIC}/set/123-46", b"ON")
        result = await self.client.async_parse_mqtt_msg(msg)
        self.assertIsInstance(result, bool)
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()

