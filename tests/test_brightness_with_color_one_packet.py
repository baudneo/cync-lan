"""Brightness + colour (or colour temp) in ONE MQTT message must reach the light as ONE packet carrying both.

Seen on a type 75 string light at 25 %: {"brightness": 100, "color_temp": 5000} and {"brightness": 100, "color": white}
both left it at 25 %. The brightness went out as its own 0xF0 packet and the colour packet (brightness byte 0xFF = keep)
followed it; the light kept its old brightness. The 0xF0 payload already has a brightness byte, so one packet can carry both.
"""
import struct
import unittest
from types import SimpleNamespace

from cync_lan import mqtt_client as mqtt_mod
from cync_lan.devices import device as device_mod


class _RecNode:
    def __init__(self, sol=False):
        self.id = 1
        self.is_fan_controller = False
        self.is_sol_lamp = sol
        self.entities = {}
        self.calls = []

    def _rec(name):
        async def f(self, *a, **k):
            self.calls.append((name, a, k))
            return True
        return f

    set_power = _rec("set_power")
    set_brightness = _rec("set_brightness")
    set_temperature = _rec("set_temperature")
    set_rgb = _rec("set_rgb")
    set_lightshow = _rec("set_lightshow")


class TestOneCallFromMqtt(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        mqtt_mod.MQTTClient._instance = None
        mqtt_mod.g.ncync_server = SimpleNamespace(node_devices={})
        mqtt_mod.g.env = SimpleNamespace(app_mitm_logging=False)
        self.client = mqtt_mod.MQTTClient()
        self.client.kelvin2cync = lambda k, node: 50

    async def _run(self, node, body):
        tasks = []
        ok = self.client._queue_json_payload(node, body.encode(), None, tasks, "t:")
        for t in tasks:
            await t
        return ok

    async def test_brightness_and_color_temp_is_one_call(self):
        n = _RecNode()
        self.assertTrue(await self._run(n, '{"state":"ON","brightness":100,"color_temp":5000}'))
        self.assertEqual([c[0] for c in n.calls], ["set_temperature"])
        self.assertEqual(n.calls[0][2].get("bri"), 100)

    async def test_brightness_and_rgb_is_one_call(self):
        n = _RecNode()
        self.assertTrue(await self._run(n, '{"state":"ON","brightness":50,"color":{"r":255,"g":0,"b":0}}'))
        self.assertEqual([c[0] for c in n.calls], ["set_rgb"])
        self.assertEqual(n.calls[0][1][:3], (255, 0, 0))
        self.assertEqual(n.calls[0][2].get("bri"), 50)

    async def test_brightness_alone_unchanged(self):
        n = _RecNode()
        self.assertTrue(await self._run(n, '{"state":"ON","brightness":25}'))
        self.assertEqual([c[0] for c in n.calls], ["set_brightness"])

    async def test_bad_color_temp_keeps_the_brightness(self):
        n = _RecNode()
        await self._run(n, '{"state":"ON","brightness":40,"color_temp":"x"}')
        self.assertEqual([c[0] for c in n.calls], ["set_brightness"])

    async def test_sol_lamp_stays_two_calls(self):
        n = _RecNode(sol=True)
        await self._run(n, '{"state":"ON","brightness":100,"color_temp":5000}')
        self.assertEqual([c[0] for c in n.calls], ["set_brightness", "set_temperature"])


class TestOnePacket(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.sent = []
        self.upd = []
        rec = self

        async def send_command(op, cmd_, sub, payload, m_cb, lp):
            rec.sent.append(payload)
            if callable(m_cb.callback):
                await m_cb.callback()

        def upd(name):
            async def f(*a, **k):
                rec.upd.append((name, a[1:]))
                return True
            return f

        device_mod.g.mqtt_client = SimpleNamespace(update_temperature=upd("temp"), update_rgb=upd("rgb"),
                                                   update_brightness=upd("bri"))
        self.node = SimpleNamespace(lp="t:", is_sol_lamp=False, send_command=send_command)

    async def test_color_temp_packet_carries_brightness(self):
        await device_mod.CyncDevice.set_temperature(self.node, 50, None, bri=100)
        self.assertEqual(self.sent, [struct.pack(">BBBBBBBB", 0x11, 0x02, 0x01, 100, 50, 0, 0, 0)])
        self.assertEqual([u[0] for u in self.upd], ["temp", "bri"])

    async def test_rgb_packet_carries_brightness(self):
        await device_mod.CyncDevice.set_rgb(self.node, 255, 255, 255, None, bri=100)
        self.assertEqual(self.sent, [struct.pack(">BBBBBBBB", 0x11, 0x02, 0x01, 100, 0xFE, 255, 255, 255)])
        self.assertEqual([u[0] for u in self.upd], ["rgb", "bri"])

    async def test_without_brightness_packet_unchanged(self):
        await device_mod.CyncDevice.set_temperature(self.node, 50, None)
        self.assertEqual(self.sent, [struct.pack(">BBBBBBBB", 0x11, 0x02, 0x01, 0xFF, 50, 0, 0, 0)])
        self.assertEqual([u[0] for u in self.upd], ["temp"])

    async def test_brightness_out_of_range_sends_nothing(self):
        await device_mod.CyncDevice.set_temperature(self.node, 50, None, bri=101)
        await device_mod.CyncDevice.set_rgb(self.node, 1, 2, 3, None, bri=-1)
        self.assertEqual(self.sent, [])
        self.assertEqual(self.upd, [])


if __name__ == "__main__":
    unittest.main()
