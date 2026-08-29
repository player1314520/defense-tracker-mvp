# -*- coding: utf-8 -*-
"""设备 token（auth_devices）：发放/校验/吊销 单测 + 端点冒烟。"""
import importlib
import logging

import pytest


@pytest.fixture()
def devices(tmp_path, monkeypatch):
    """隔离库：把 DB 指到 tmp，重建表，测试互不污染。"""
    import auth_devices
    monkeypatch.setattr(auth_devices, "DB_FILE", str(tmp_path / "us.sqlite3"))
    auth_devices._VERIFY_CACHE.clear()
    auth_devices.init_device_db()
    return auth_devices


def test_issue_then_verify(devices):
    plaintext, dev_id = devices.issue_device_token("手机")
    assert len(plaintext) > 20 and dev_id >= 1
    assert devices.verify_device_token(plaintext) is True


def test_wrong_token_rejected(devices):
    devices.issue_device_token("手机")
    assert devices.verify_device_token("not-a-real-token") is False
    assert devices.verify_device_token("") is False
    assert devices.verify_device_token(None) is False


def test_revoke_takes_effect_immediately(devices):
    plaintext, dev_id = devices.issue_device_token("旧笔记本")
    assert devices.verify_device_token(plaintext) is True
    assert devices.revoke_device(dev_id) is True
    # 吊销清缓存，立即失效
    assert devices.verify_device_token(plaintext) is False
    # 重复吊销返回 False
    assert devices.revoke_device(dev_id) is False


def test_list_shows_hint_not_token(devices):
    plaintext, _ = devices.issue_device_token("网页")
    rows = devices.list_devices()
    assert len(rows) == 1
    assert rows[0]["device_name"] == "网页"
    assert rows[0]["hint"] == plaintext[:6]
    # 库里绝不出现明文
    assert all(plaintext not in str(v) for v in rows[0].values())


def test_hash_stored_not_plaintext(devices):
    plaintext, _ = devices.issue_device_token("x")
    with devices._conn() as conn:
        row = conn.execute("SELECT token_hash FROM device_tokens").fetchone()
    assert row["token_hash"] != plaintext
    assert len(row["token_hash"]) == 64  # sha256 hex


def test_device_name_is_bounded_in_storage_and_excluded_from_logs(devices, caplog):
    supplied = "终端\r\n伪造日志\u2028" + ("A" * 100)

    with caplog.at_level(logging.INFO, logger="auth_devices"):
        devices.issue_device_token(supplied)

    stored = devices.list_devices()[0]["device_name"]
    assert stored == "终端 伪造日志 " + ("A" * 56)
    assert len(stored) == 64
    assert "\r" not in stored and "\n" not in stored and "\u2028" not in stored
    message = caplog.records[-1].getMessage()
    assert message.startswith("设备 token 已发放: id=")
    assert stored not in message
    assert supplied not in message


def test_endpoints_issue_and_revoke(monkeypatch, tmp_path):
    """端点冒烟：POST 发放 → GET 列表 → POST 吊销。"""
    import app as tracker
    import auth_devices
    monkeypatch.setattr(auth_devices, "DB_FILE", str(tmp_path / "us.sqlite3"))
    auth_devices._VERIFY_CACHE.clear()
    auth_devices.init_device_db()

    client = tracker.app.test_client()
    csrf = "csrf-test-token"
    client.set_cookie(tracker.CSRF_COOKIE, csrf)
    hdr = {"X-CSRF-Token": csrf}

    r = client.post("/api/auth/devices", json={"name": "测试手机"}, headers=hdr)
    assert r.status_code == 201
    data = r.get_json()
    assert data["token"] and data["hint"] == data["token"][:6]
    dev_id = data["id"]

    r = client.get("/api/auth/devices")
    assert r.status_code == 200
    assert any(d["id"] == dev_id for d in r.get_json()["devices"])

    r = client.post(f"/api/auth/devices/{dev_id}/revoke", headers=hdr)
    assert r.status_code == 200
    r = client.post(f"/api/auth/devices/{dev_id}/revoke", headers=hdr)
    assert r.status_code == 404


def test_auth_accepts_device_token_when_required(monkeypatch, tmp_path):
    """AUTH_REQUIRED 开启时：设备 token 与 master token 均可通过 _is_authenticated。"""
    import app as tracker
    import auth_devices
    monkeypatch.setattr(auth_devices, "DB_FILE", str(tmp_path / "us.sqlite3"))
    auth_devices._VERIFY_CACHE.clear()
    auth_devices.init_device_db()
    plaintext, _ = auth_devices.issue_device_token("手机")

    monkeypatch.setattr(tracker, "AUTH_REQUIRED", True)
    monkeypatch.setattr(tracker, "ACCESS_TOKEN", "master-token-xyz")

    with tracker.app.test_request_context(headers={"X-Access-Token": plaintext}):
        assert tracker._is_authenticated() is True
    with tracker.app.test_request_context(headers={"X-Access-Token": "master-token-xyz"}):
        assert tracker._is_authenticated() is True
    with tracker.app.test_request_context(headers={"X-Access-Token": "bogus"}):
        assert tracker._is_authenticated() is False
    with tracker.app.test_request_context():
        assert tracker._is_authenticated() is False
