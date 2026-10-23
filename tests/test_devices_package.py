"""Guards the devices/ package layout: the split must keep the public API and MRO intact."""

import inspect

from cync_lan.devices import CyncDevice, CyncTCPSession
from cync_lan.devices.handlers import PacketHandlersMixin
from cync_lan.devices.proxy import ProxyMixin


def test_public_api():
    assert inspect.isclass(CyncDevice) and inspect.isclass(CyncTCPSession)


def test_session_composes_mixins():
    assert issubclass(CyncTCPSession, ProxyMixin)
    assert issubclass(CyncTCPSession, PacketHandlersMixin)


def test_session_has_all_handlers():
    for name in (
        "parse_raw_data", "parse_packet", "_dispatch_device_request", "_handle_43_packet",
        "_handle_83_packet", "_handle_73_mesh_control", "start_mitm", "stop_proxy",
        "can_connect", "receive_task", "write", "close",
    ):
        assert callable(getattr(CyncTCPSession, name)), name
