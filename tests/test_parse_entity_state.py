"""parse_entity_state must publish for every device, including a deviceType model_info does not know yet."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest_asyncio

from cync_lan import mqtt_client as m
from cync_lan.devices.device import CyncDevice
from cync_lan.metadata.model_info import device_type_map
from cync_lan.structs import EntityState


class _Server:
    def __init__(self):
        self.node_devices = {}


def _node(metadata, rgb=True):
    entity = SimpleNamespace(power=1, brightness=64, temperature=0xA7, red=0, green=0, blue=0, motion=0)
    return SimpleNamespace(
        id=1, type=None, hass_id="123-1", entities={0: entity}, metadata=metadata, is_fan_controller=False, is_plug=False,
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


async def test_mesh_status_for_an_unknown_type_does_not_block_the_next_device(client):
    """The 0x73 mesh-info path (handlers._process_73_mesh_info -> CyncDevice.handle_entity_update -> parse_entity_state) hit the
    same AttributeError for a deviceType model_info does not know: the whole mesh packet was dropped, so status from the KNOWN
    devices in it stopped too (reported in #48 with two type-171 bulbs in a 19-device mesh). Each status must publish."""
    assert 250 not in device_type_map
    m.g.mqtt_client = client
    m.g.tasks = []
    client.pub_online = AsyncMock(return_value=True)
    unknown, known = CyncDevice(1, dev_type=250, name="new bulb", entities={}), CyncDevice(2, dev_type=75, name="string", entities={})
    m.g.ncync_server.node_devices.update({1: unknown, 2: known})
    for dev_id in (1, 2):
        state = EntityState(dev_id=dev_id, name="x", power=1, brightness=50, temperature=254, red=255)
        assert await m.g.ncync_server.node_devices[dev_id].handle_entity_update(state, from_pkt="0x73") is True
    assert client.pub_entity_state.await_count == 2
