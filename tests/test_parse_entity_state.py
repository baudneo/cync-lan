"""parse_entity_state must publish for every device, including a deviceType model_info does not know yet."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest_asyncio

from cync_lan import mqtt_client as m


class _Server:
    def __init__(self):
        self.node_devices = {}


def _node(metadata, rgb=True):
    entity = SimpleNamespace(power=1, brightness=64, temperature=0xA7, red=0, green=0, blue=0, motion=0)
    return SimpleNamespace(
        id=1, hass_id="123-1", entities={0: entity}, metadata=metadata, is_fan_controller=False, is_plug=False,
        is_switch=False, supports_rgb=rgb, supports_temperature=True,
    ), entity


@pytest_asyncio.fixture
async def client():
    m.MQTTClient._instance = None
    m.g.ncync_server = _Server()
    m.g.env = SimpleNamespace(app_mitm_logging=False)
    c = m.MQTTClient()
    c.pub_entity_state = AsyncMock(return_value=True)
    return c


async def test_state_without_metadata_does_not_raise(client):
    """An unknown deviceType has metadata None; the HA-birth re-announce used to stop at the first one (AttributeError)."""
    node, entity = _node(metadata=None)
    m.g.ncync_server.node_devices[1] = node
    entity.dev_id, entity.sub_id = 1, 0
    assert await client.parse_entity_state(entity) is True
