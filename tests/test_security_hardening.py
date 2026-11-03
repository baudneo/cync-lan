"""Exporter / file-permission / secret-key hardening (PLAN.md review items 1-4, 8, 12)."""

import os
import stat
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from cync_lan import cloud_api, exporter, utils


def mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


# ---- cross-site protection
@pytest.mark.parametrize(
    "origin, host, ok",
    [
        (None, "10.0.0.5:23778", True),  # curl / healthcheck / same-origin GET
        ("http://10.0.0.5:23778", "10.0.0.5:23778", True),  # the UI itself
        ("http://evil.example", "10.0.0.5:23778", False),
        ("null", "10.0.0.5:23778", False),  # sandboxed iframe / file://
        ("http://10.0.0.5:9999", "10.0.0.5:23778", False),  # same host, other port
        ("HTTP://10.0.0.5:23778/", "10.0.0.5:23778", True),
    ],
)
def test_origin_allowed(origin, host, ok):
    assert exporter.origin_allowed(origin, host) is ok


def test_extra_allowed_origin(monkeypatch):
    monkeypatch.setattr(exporter, "_EXTRA_ORIGINS", {"https://proxy.example"})
    assert exporter.origin_allowed("https://proxy.example", "internal:23778")


TOKEN = "test-token-123"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setattr(exporter, "CYNC_HASS_APP", False)
    monkeypatch.setattr(exporter, "CYNC_EXPORT_TOKEN", TOKEN)
    exporter.g.cync_lan = SimpleNamespace(stop=AsyncMock())
    return TestClient(exporter.app, base_url="http://10.0.0.5:23778", headers=AUTH)


def test_cross_site_restart_is_blocked(api):
    r = api.post("/api/restart", headers={**AUTH, "Origin": "http://evil.example"})
    assert r.status_code == 403
    exporter.g.cync_lan.stop.assert_not_called()


def test_cross_site_download_is_blocked(api):
    r = api.get("/api/export/download", headers={**AUTH, "Origin": "http://evil.example"})
    assert r.status_code == 403


def test_same_origin_restart_works_and_reports_success(api):
    r = api.post("/api/restart", headers={**AUTH, "Origin": "http://10.0.0.5:23778"})
    assert r.status_code == 200 and r.json()["success"] is True
    exporter.g.cync_lan.stop.assert_awaited_once()


def test_no_wildcard_cors_headers(api):
    r = api.get("/api/healthcheck", headers={**AUTH, "Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in r.headers


@pytest.mark.parametrize("path", ["/api/export/start", "/api/export/otp/request"])
def test_state_changing_endpoints_reject_get(api, path):
    assert api.get(path).status_code == 405


# ---- access token
@pytest.mark.parametrize(
    "path, method",
    [("/api/restart", "post"), ("/api/export/download", "get"), ("/api/export/start", "post"),
     ("/api/export/otp/request", "post"), ("/api/export/otp/submit", "post")],
)
def test_api_requires_token(api, path, method):
    no_auth = TestClient(exporter.app, base_url="http://10.0.0.5:23778")
    r = getattr(no_auth, method)(path)
    assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"
    wrong = getattr(no_auth, method)(path, headers={"Authorization": "Bearer nope"})
    assert wrong.status_code == 401
    exporter.g.cync_lan.stop.assert_not_called()


def test_healthcheck_and_ui_shell_are_public(api):
    no_auth = TestClient(exporter.app, base_url="http://10.0.0.5:23778")
    assert no_auth.get("/api/healthcheck").status_code == 200


def test_ingress_mode_skips_token_and_origin_checks(api, monkeypatch):
    monkeypatch.setattr(exporter, "CYNC_HASS_APP", True)
    no_auth = TestClient(exporter.app, base_url="http://172.30.33.5:23778")
    r = no_auth.get("/api/healthcheck", headers={"Origin": "https://ha.example"})
    assert r.status_code == 200


def test_token_ok():
    assert exporter.token_ok("Bearer abc", "abc")
    assert exporter.token_ok("bearer abc", "abc")
    assert not exporter.token_ok("Bearer abd", "abc")
    assert not exporter.token_ok("Basic abc", "abc")
    assert not exporter.token_ok(None, "abc")
    assert not exporter.token_ok("Bearer ", "")  # no token configured -> deny everything
    assert not exporter.token_ok("Bearer x", None)


def test_export_token_derivation(monkeypatch):
    monkeypatch.setattr(exporter, "CYNC_EXPORT_TOKEN", None)
    monkeypatch.setattr(exporter, "CYNC_SECRET_KEY", "my secret key")
    t1 = exporter.export_token()
    assert t1 and len(t1) == 32 and "secret" not in t1
    assert exporter.export_token() == t1  # stable across restarts
    monkeypatch.setattr(exporter, "CYNC_SECRET_KEY", "another key")
    assert exporter.export_token() != t1
    monkeypatch.setattr(exporter, "CYNC_SECRET_KEY", None)
    assert exporter.export_token() is None
    monkeypatch.setattr(exporter, "CYNC_EXPORT_TOKEN", "fixed")
    assert exporter.export_token() == "fixed"


def test_export_host_defaults_to_loopback():
    import importlib

    import cync_lan.const as const

    env = {k: v for k, v in os.environ.items() if k not in ("CYNC_EXPORT_HOST", "CYNC_HASS_APP")}
    saved = dict(os.environ)
    try:
        os.environ.clear()
        os.environ.update(env)
        assert importlib.reload(const).CYNC_EXPORT_HOST == "127.0.0.1"
        os.environ["CYNC_HASS_APP"] = "yes"
        assert importlib.reload(const).CYNC_EXPORT_HOST == "0.0.0.0"
        os.environ["CYNC_EXPORT_HOST"] = "10.1.2.3"
        assert importlib.reload(const).CYNC_EXPORT_HOST == "10.1.2.3"
    finally:
        os.environ.clear()
        os.environ.update(saved)
        importlib.reload(const)


# ---- file permissions
def test_write_private_file_is_never_world_readable(tmp_path):
    old = os.umask(0)  # worst case: permissive umask
    try:
        p = tmp_path / "secret.yaml"
        utils.write_private_file(p, "access_key: abc")
        assert mode(p) == 0o600
        assert p.read_text() == "access_key: abc"
    finally:
        os.umask(old)


def test_write_private_file_tightens_existing_file(tmp_path):
    p = tmp_path / "token"
    p.write_bytes(b"old")
    os.chmod(p, 0o777)
    utils.write_private_file(p, b"new")
    assert mode(p) == 0o600 and p.read_bytes() == b"new"


# ---- uuid.txt handling
def _point_utils_at(monkeypatch, tmp_path):
    monkeypatch.setattr(utils, "CYNC_CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(utils, "CYNC_UUID_PATH", str(tmp_path / "uuid.txt"))


def test_corrupt_uuid_file_is_regenerated_not_fatal(tmp_path, monkeypatch):
    _point_utils_at(monkeypatch, tmp_path)
    (tmp_path / "uuid.txt").write_text("this-is-not-a-uuid")
    utils.check_for_uuid()
    new = (tmp_path / "uuid.txt").read_text().strip()
    assert uuid.UUID(new).version == 4
    assert utils.g.uuid == uuid.UUID(new)


def test_valid_uuid_file_is_kept(tmp_path, monkeypatch):
    _point_utils_at(monkeypatch, tmp_path)
    keep = uuid.uuid4()
    (tmp_path / "uuid.txt").write_text(str(keep))
    utils.check_for_uuid()
    assert utils.g.uuid == keep


def test_unwritable_uuid_dir_does_not_crash(tmp_path, monkeypatch):
    _point_utils_at(monkeypatch, tmp_path)
    monkeypatch.setattr(utils, "write_private_file", lambda *a, **k: (_ for _ in ()).throw(PermissionError("ro")))
    utils.check_for_uuid()  # must not raise
    assert utils.g.uuid is not None


# ---- secret key
def test_missing_secret_key_raises_cleanly(monkeypatch):
    monkeypatch.setattr(cloud_api, "CYNC_SECRET_KEY", "")
    with pytest.raises(RuntimeError, match="CYNC_SECRET_KEY"):
        cloud_api.CyncCloudAPI._get_fernet_cipher(None)


def test_secret_key_roundtrip(monkeypatch):
    monkeypatch.setattr(cloud_api, "CYNC_SECRET_KEY", "correct horse battery staple")
    cipher = cloud_api.CyncCloudAPI._get_fernet_cipher(None)
    assert cipher.decrypt(cipher.encrypt(b"token")) == b"token"
