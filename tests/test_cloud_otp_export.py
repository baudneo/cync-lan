"""OTP handling, properties-fetch errors, export result reporting (PLAN.md exporter items 5, 7, 9)."""

import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock

import aiohttp
import pytest
from fastapi.testclient import TestClient

from cync_lan import cloud_api, exporter


def make_api():
    api = object.__new__(cloud_api.CyncCloudAPI)
    api.lp = "t"
    api.api_timeout = 5
    api._check_session = AsyncMock()
    api._send_tkn_post = AsyncMock(return_value=True)
    api.token_cache = SimpleNamespace(access_token="tok")
    return api


@pytest.fixture
def creds(monkeypatch):
    monkeypatch.setattr(cloud_api, "CYNC_ACCOUNT_USERNAME", "u@example.com")
    monkeypatch.setattr(cloud_api, "CYNC_ACCOUNT_PASSWORD", "pw")


async def test_non_numeric_otp_is_not_sent(creds):
    api = make_api()
    assert await api.send_otp("12ab") is False
    api._send_tkn_post.assert_not_awaited()


async def test_otp_not_logged(creds, caplog):
    caplog.set_level(logging.DEBUG)
    api = make_api()
    assert await api.send_otp(" 987654 ") is True
    assert "987654" not in caplog.text
    assert api._send_tkn_post.await_args.args[1]["two_factor"] == "987654"


async def test_send_otp_without_password_does_not_crash(monkeypatch):
    monkeypatch.setattr(cloud_api, "CYNC_ACCOUNT_USERNAME", "u")
    monkeypatch.setattr(cloud_api, "CYNC_ACCOUNT_PASSWORD", None)
    api = make_api()
    assert await api.send_otp("123456") is False


class _Resp:
    def __init__(self, data=None, status_exc=None):
        self._data, self._exc = data, status_exc

    def raise_for_status(self):
        if self._exc:
            raise self._exc

    async def json(self):
        return self._data


async def test_properties_http_error_raises_clear_error():
    api = make_api()
    exc = aiohttp.ClientResponseError(SimpleNamespace(real_url="http://x"), (), status=500)
    api.http_session = SimpleNamespace(get=AsyncMock(return_value=_Resp(status_exc=exc)))
    with pytest.raises(RuntimeError):
        await api.get_cync_home_properties("p", "d")


async def test_properties_non_dict_error_field_tolerated():
    api = make_api()
    api.http_session = SimpleNamespace(get=AsyncMock(return_value=_Resp({"error": "boom"})))
    assert await api.get_cync_home_properties("p", "d") == {"error": "boom"}


@pytest.fixture
def api_client(monkeypatch):
    monkeypatch.setattr(exporter, "CYNC_HASS_APP", False)
    monkeypatch.setattr(exporter, "CYNC_EXPORT_TOKEN", "t")
    monkeypatch.setattr(exporter, "CYNC_EXPORT_SOURCE", "/some/file")
    return TestClient(exporter.app, base_url="http://10.0.0.5:23778", headers={"Authorization": "Bearer t"})


def test_export_start_reports_failure(api_client):
    exporter.g.cloud_api = SimpleNamespace(export_config_file=AsyncMock(return_value=False))
    body = api_client.post("/api/export/start").json()
    assert body["success"] is False


def test_export_start_exception_is_502(api_client):
    exporter.g.cloud_api = SimpleNamespace(export_config_file=AsyncMock(side_effect=RuntimeError("x")))
    assert api_client.post("/api/export/start").status_code == 502


def test_export_start_success(api_client):
    exporter.g.cloud_api = SimpleNamespace(export_config_file=AsyncMock(return_value=True))
    assert api_client.post("/api/export/start").json()["success"] is True
