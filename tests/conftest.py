import pytest

from cync_lan.devices import device as device_mod


@pytest.fixture(autouse=True)
def _no_command_batching(monkeypatch):
    """Tests expect a command to be written at once; batching (CYNC_CMD_BATCH_MS) has its own tests."""
    monkeypatch.setattr(device_mod, "CYNC_CMD_BATCH_MS", 0)
    device_mod._BATCH_BRIDGES.clear()
    yield
    device_mod._BATCH_BRIDGES.clear()
