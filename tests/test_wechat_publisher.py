import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import threading
from types import ModuleType, SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wechat_publisher import (
    ApiError,
    ApprovalError,
    IdempotencyConflict,
    ManifestError,
    PublicationLedger,
    PublicationService,
    WeChatApiClient,
    WechatCredentialVault,
    build_approval,
    compute_manifest_hashes,
    validate_manifest,
)


APPROVAL_PRIVATE_KEY = Ed25519PrivateKey.generate()
APPROVAL_PUBLIC_KEY_PEM = APPROVAL_PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("ascii")


def _approved_at_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _signed_approval_at(manifest, approved_at):
    hashes = compute_manifest_hashes(manifest)
    unsigned = {
        "algorithm": "Ed25519",
        "scope": ":".join(
            [
                "wechat-publication-v1",
                manifest["channel"],
                manifest["publication_date"],
                manifest["edition"],
                manifest["delivery"],
            ]
        ),
        **hashes,
        "approved_at": approved_at,
    }
    encoded = json.dumps(
        unsigned,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        **unsigned,
        "signature": base64.b64encode(APPROVAL_PRIVATE_KEY.sign(encoded)).decode("ascii"),
    }


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        if not self.responses:
            raise AssertionError(f"unexpected POST {url}")
        return self.responses.pop(0)


def _manifest(*, delivery="draft", content="<p>已核验的公开信息。</p>"):
    return {
        "channel": "wechat_official",
        "publication_date": "2026-08-14",
        "edition": "daily",
        "delivery": delivery,
        "article": {
            "title": "每日防务简报",
            "author": "防务开源情报",
            "digest": "仅整理可公开核验信息。",
            "content": content,
            "content_source_url": "https://example.org/brief/2026-08-14",
            "thumb_media_id": "cover-media-id",
        },
        "sources": [
            {
                "title": "Official release",
                "publisher": "Official Agency",
                "url": "https://example.org/source/1",
                "published_at": "2026-08-14",
            }
        ],
    }


def _service(
    tmp_path,
    responses,
    *,
    enabled=False,
    approval_public_key=None,
    attempts=1,
):
    session = FakeSession([FakeResponse(item) for item in responses])
    client = WeChatApiClient("wx-app-id", "super-secret", session=session)
    ledger = PublicationLedger(tmp_path / "wechat.sqlite3")
    service = PublicationService(
        client,
        ledger,
        publish_enabled=enabled,
        approval_public_key=approval_public_key,
        poll_attempts=attempts,
        poll_interval=0,
    )
    return service, session


def test_api_business_errcode_fails_closed_without_leaking_secret():
    session = FakeSession([FakeResponse({"errcode": 40013, "errmsg": "invalid appid super-secret"})])
    client = WeChatApiClient("wx-app-id", "super-secret", session=session)

    with pytest.raises(ApiError) as exc_info:
        client.add_draft({"title": "x"})

    message = str(exc_info.value)
    assert "40013" in message
    assert "super-secret" not in message


def test_api_uses_official_endpoints_and_checks_each_success_shape():
    session = FakeSession(
        [
            FakeResponse({"access_token": "token-secret", "expires_in": 7200}),
            FakeResponse({"media_id": "draft-id"}),
            FakeResponse({"publish_id": "publish-id", "msg_data_id": "data-id"}),
            FakeResponse({"publish_status": 0, "article_id": "article-id"}),
            FakeResponse({"errcode": 0, "errmsg": "send job submission success", "msg_id": 123}),
            FakeResponse({"msg_id": 123, "msg_status": "SEND_SUCCESS"}),
        ]
    )
    client = WeChatApiClient("wx-app-id", "super-secret", session=session)

    assert client.add_draft({"title": "x"})["media_id"] == "draft-id"
    assert client.submit_publish("draft-id")["publish_id"] == "publish-id"
    assert client.get_publish_status("publish-id")["publish_status"] == 0
    assert client.mass_send_all("draft-id", "client-message-id")["msg_id"] == 123
    assert client.mass_get(123)["msg_status"] == "SEND_SUCCESS"

    assert session.calls[0]["url"].endswith("/cgi-bin/stable_token")
    assert session.calls[1]["url"].endswith("/cgi-bin/draft/add")
    assert session.calls[2]["url"].endswith("/cgi-bin/freepublish/submit")
    assert session.calls[3]["url"].endswith("/cgi-bin/freepublish/get")
    assert session.calls[4]["url"].endswith("/cgi-bin/message/mass/sendall")
    assert session.calls[5]["url"].endswith("/cgi-bin/message/mass/get")
    assert session.calls[4]["json"]["clientmsgid"] == "client-message-id"


def test_mass_status_rehydrates_numeric_msg_id_from_sqlite_text():
    session = FakeSession(
        [
            FakeResponse({"access_token": "token-secret", "expires_in": 7200}),
            FakeResponse({"msg_id": 123, "msg_status": "SEND_SUCCESS"}),
        ]
    )
    client = WeChatApiClient("wx-app-id", "super-secret", session=session)

    client.mass_get("123")

    assert session.calls[-1]["json"]["msg_id"] == 123


def test_default_disabled_stages_one_draft_and_is_idempotent(tmp_path):
    manifest = _manifest(delivery="mass")
    service, session = _service(
        tmp_path,
        [
            {"access_token": "token-secret", "expires_in": 7200},
            {"media_id": "draft-id"},
        ],
    )

    first = service.run(manifest)
    second = service.run(manifest)

    assert first["state"] == "pending_approval"
    assert first["requires_approval"] is True
    assert first["delivery_verified"] is False
    assert second["state"] == "pending_approval"
    assert len([call for call in session.calls if call["url"].endswith("/draft/add")]) == 1
    assert not any("/mass/sendall" in call["url"] for call in session.calls)


def test_same_daily_key_rejects_changed_content(tmp_path):
    service, _ = _service(
        tmp_path,
        [
            {"access_token": "token-secret", "expires_in": 7200},
            {"media_id": "draft-id"},
        ],
    )
    service.run(_manifest())

    with pytest.raises(IdempotencyConflict):
        service.run(_manifest(content="<p>内容已被更换。</p>"))


def test_publish_requires_hash_bound_signed_approval_before_network(tmp_path):
    manifest = _manifest(delivery="publish")
    manifest["approval"] = {
        "scope": "wrong",
        "content_sha256": "0" * 64,
        "source_sha256": "0" * 64,
        "approved_at": "2026-08-14T21:00:00+08:00",
        "algorithm": "Ed25519",
        "signature": base64.b64encode(b"0" * 64).decode("ascii"),
    }
    service, session = _service(
        tmp_path,
        [],
        enabled=True,
        approval_public_key=APPROVAL_PUBLIC_KEY_PEM,
    )

    with pytest.raises(ApprovalError):
        service.run(manifest)

    assert session.calls == []


def test_publish_submission_is_not_success_until_status_backcheck(tmp_path):
    manifest = _manifest(delivery="publish")
    manifest["approval"] = build_approval(
        manifest,
        APPROVAL_PRIVATE_KEY,
        approved_at=_approved_at_now(),
    )
    service, session = _service(
        tmp_path,
        [
            {"access_token": "token-secret", "expires_in": 7200},
            {"media_id": "draft-id"},
            {"publish_id": "publish-id", "msg_data_id": "data-id"},
            {"publish_status": 1},
        ],
        enabled=True,
        approval_public_key=APPROVAL_PUBLIC_KEY_PEM,
    )

    result = service.run(manifest)

    assert result["state"] == "publishing"
    assert result["submitted_not_verified"] is True
    assert result["delivery_verified"] is False
    assert any(call["url"].endswith("/freepublish/get") for call in session.calls)


def test_publish_marks_verified_only_after_platform_success(tmp_path):
    manifest = _manifest(delivery="publish")
    manifest["approval"] = build_approval(
        manifest,
        APPROVAL_PRIVATE_KEY,
        approved_at=_approved_at_now(),
    )
    service, _ = _service(
        tmp_path,
        [
            {"access_token": "token-secret", "expires_in": 7200},
            {"media_id": "draft-id"},
            {"publish_id": "publish-id"},
            {
                "publish_status": 0,
                "article_id": "article-id",
                "article_detail": {"item": [{"article_url": "https://mp.weixin.qq.com/s/example"}]},
            },
        ],
        enabled=True,
        approval_public_key=APPROVAL_PUBLIC_KEY_PEM,
    )

    result = service.run(manifest)

    assert result["state"] == "published"
    assert result["delivery_verified"] is True
    assert result["article_url"] == "https://mp.weixin.qq.com/s/example"


def test_mass_send_uses_deterministic_clientmsgid_and_checks_delivery(tmp_path):
    manifest = _manifest(delivery="mass")
    manifest["approval"] = build_approval(
        manifest,
        APPROVAL_PRIVATE_KEY,
        approved_at=_approved_at_now(),
    )
    service, session = _service(
        tmp_path,
        [
            {"access_token": "token-secret", "expires_in": 7200},
            {"media_id": "draft-id"},
            {"errcode": 0, "errmsg": "ok", "msg_id": 123},
            {"msg_id": 123, "msg_status": "SEND_SUCCESS"},
        ],
        enabled=True,
        approval_public_key=APPROVAL_PUBLIC_KEY_PEM,
    )

    result = service.run(manifest)

    mass_call = next(call for call in session.calls if call["url"].endswith("/message/mass/sendall"))
    assert mass_call["json"]["clientmsgid"].startswith("dt-20260814-daily-")
    assert mass_call["json"]["filter"] == {"is_to_all": True}
    assert result["state"] == "delivered"
    assert result["delivery_verified"] is True
    assert any(call["url"].endswith("/message/mass/get") for call in session.calls)


def test_manifest_hashes_are_stable_and_do_not_include_approval():
    manifest = _manifest()
    before = compute_manifest_hashes(manifest)
    manifest["approval"] = {"signature": "irrelevant"}
    after = compute_manifest_hashes(manifest)

    assert before == after
    assert len(before["content_sha256"]) == 64
    assert len(before["source_sha256"]) == 64
    json.dumps(before)


def test_credential_vault_encrypts_the_entire_json_with_injected_protector(tmp_path):
    class FakeProtector:
        prefix = b"fake-dpapi:"

        def protect(self, value):
            return self.prefix + value[::-1]

        def unprotect(self, value):
            assert value.startswith(self.prefix)
            return value[len(self.prefix) :][::-1]

    vault = WechatCredentialVault(tmp_path / ".wechat_mp.vault", protector=FakeProtector())
    expected = {
        "app_id": "wx-test-app",
        "app_secret": "secret-not-for-disk",
        "thumb_media_id": "cover-media-id",
        "approval_public_key": APPROVAL_PUBLIC_KEY_PEM,
    }

    vault.save(expected)

    stored = (tmp_path / ".wechat_mp.vault").read_text(encoding="utf-8")
    assert "wx-test-app" not in stored
    assert "secret-not-for-disk" not in stored
    assert "cover-media-id" not in stored
    assert APPROVAL_PUBLIC_KEY_PEM not in stored
    assert vault.load() == expected


def test_missing_vault_does_not_initialize_windows_dpapi(tmp_path, monkeypatch):
    import v9.supabase_client as supabase_client

    monkeypatch.setattr(
        supabase_client,
        "WindowsDpapiProtector",
        lambda: pytest.fail("missing vault must not initialize Windows DPAPI"),
    )

    vault = WechatCredentialVault(tmp_path / ".wechat_mp.vault")

    assert vault.load() is None


def test_vault_rejects_any_approval_private_key_material(tmp_path):
    class FakeProtector:
        def protect(self, value):
            return value

        def unprotect(self, value):
            return value

    vault = WechatCredentialVault(tmp_path / ".wechat_mp.vault", protector=FakeProtector())

    with pytest.raises(ValueError):
        vault.save(
            {
                "app_id": "wx-test-app",
                "app_secret": "secret-not-for-disk",
                "approval_private_key": "-----BEGIN " + "PRIVATE KEY-----",
            }
        )


def test_vault_rejects_private_key_pem_in_approval_public_key_field(tmp_path):
    class FakeProtector:
        def protect(self, value):
            return value

        def unprotect(self, value):
            return value

    private_key_pem = APPROVAL_PRIVATE_KEY.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    vault = WechatCredentialVault(tmp_path / ".wechat_mp.vault", protector=FakeProtector())

    with pytest.raises(ValueError, match="private keys are forbidden"):
        vault.save(
            {
                "app_id": "wx-test-app",
                "app_secret": "secret-not-for-disk",
                "approval_public_key": private_key_pem,
            }
        )


def _write_test_vault_envelope(path):
    plaintext = json.dumps(
        {
            "schema": 1,
            "credentials": {
                "app_id": "wx-test",
                "app_secret": "test-secret",
            },
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "protected_payload": base64.b64encode(plaintext).decode("ascii"),
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )


def _vault_file_security_check(*, current_sid, include_wide_ace, calls):
    from wechat_runtime import ensure_private_file

    def fake_runner(argv, **kwargs):
        calls.append(list(argv))
        if str(argv[0]).lower().endswith("powershell.exe"):
            entries = [
                {"sid": current_sid, "type": "Allow", "rights": "FullControl"},
                {"sid": "S-1-5-18", "type": "Allow", "rights": "FullControl"},
                {
                    "sid": "S-1-5-32-544",
                    "type": "Allow",
                    "rights": "FullControl",
                },
            ]
            if include_wide_ace:
                entries.append(
                    {
                        "sid": "S-1-5-32-545",
                        "type": "Allow",
                        "rights": "ReadAndExecute",
                    }
                )
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps({"protected": True, "entries": entries}),
                stderr="",
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    return lambda path: ensure_private_file(
        path,
        platform_name="nt",
        runner=fake_runner,
        current_user_sid=current_sid,
        junction_checker=lambda candidate: False,
        lstat_func=lambda candidate: SimpleNamespace(st_file_attributes=0),
    )


def test_vault_load_blocks_wide_windows_acl_before_decryption(tmp_path):
    from wechat_runtime import RuntimeSecurityError

    vault_path = tmp_path / ".wechat_mp.vault"
    _write_test_vault_envelope(vault_path)
    decrypt_calls = []
    permission_calls = []

    class RecordingProtector:
        def unprotect(self, value):
            decrypt_calls.append(value)
            return value

    vault = WechatCredentialVault(
        vault_path,
        protector=RecordingProtector(),
        file_security=_vault_file_security_check(
            current_sid="S-1-5-21-1000",
            include_wide_ace=True,
            calls=permission_calls,
        ),
    )

    with pytest.raises(RuntimeSecurityError):
        vault.load()

    assert decrypt_calls == []
    assert permission_calls


def test_vault_load_exact_windows_acl_allows_decryption(tmp_path):
    vault_path = tmp_path / ".wechat_mp.vault"
    _write_test_vault_envelope(vault_path)
    events = []

    class RecordingProtector:
        def unprotect(self, value):
            events.append("decrypt")
            return value

    security_check = _vault_file_security_check(
        current_sid="S-1-5-21-1000",
        include_wide_ace=False,
        calls=[],
    )

    def recording_security(path):
        security_check(path)
        events.append("secure")

    vault = WechatCredentialVault(
        vault_path,
        protector=RecordingProtector(),
        file_security=recording_security,
    )

    assert vault.load() == {"app_id": "wx-test", "app_secret": "test-secret"}
    assert events == ["secure", "decrypt"]


def _write_issue(path, *, include_cover=True):
    issue = {
        "edition_date": "2026-08-14",
        "edition": "daily",
        "title": "每日防务简报",
        "author": "防务开源情报",
        "digest": "仅整理可公开核验信息。",
        "content_html": "<p>已核验的公开信息。</p>",
        "content_source_url": "https://example.org/brief/2026-08-14",
        "source_urls": ["https://example.org/source/1"],
    }
    if include_cover:
        issue["thumb_media_id"] = "cover-media-id"
    path.write_text(json.dumps(issue, ensure_ascii=False), encoding="utf-8")


def _run_cli(tmp_path, action, *, include_cover=True, extra_env=None):
    issue_path = tmp_path / "issue.json"
    _write_issue(issue_path, include_cover=include_cover)
    env = os.environ.copy()
    for name in (
        "WECHAT_MP_APP_ID",
        "WECHAT_MP_APP_SECRET",
        "WECHAT_APPROVAL_KEY",
        "WECHAT_APPROVAL_PUBLIC_KEY",
        "WECHAT_PUBLISH_ENABLED",
        "WECHAT_THUMB_MEDIA_ID",
        "WECHAT_CREDENTIAL_SOURCE",
        "WECHAT_RUNTIME_DIR",
        "WECHAT_LEDGER_PATH",
    ):
        env.pop(name, None)
    env["WECHAT_RUNTIME_DIR"] = str(tmp_path / "runtime")
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [
            sys.executable,
            "scripts/run_daily_wechat.py",
            "--content",
            str(issue_path),
            "--action",
            action,
            "--ledger",
            str(tmp_path / "runtime" / "ledger.sqlite3"),
        ],
        cwd=os.path.dirname(os.path.dirname(__file__)),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
    )


def test_cli_prepare_needs_no_wechat_credentials_and_writes_review_state(tmp_path):
    completed = _run_cli(tmp_path, "prepare")

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["status"] == "REVIEW_PENDING"
    assert payload["delivery_verified"] is False
    assert payload["content_sha256"]
    assert (tmp_path / "runtime" / "ledger.sqlite3").is_file()


def test_cli_prepare_allows_missing_cover_but_reports_it_as_a_blocker(tmp_path):
    completed = _run_cli(tmp_path, "prepare", include_cover=False)

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["status"] == "REVIEW_PENDING"
    assert payload["blockers"] == ["THUMB_MEDIA_ID_MISSING"]
    assert payload["delivery_verified"] is False


def test_cli_draft_without_credentials_returns_structured_blocked(tmp_path):
    completed = _run_cli(tmp_path, "draft")

    assert completed.returncode == 2
    payload = json.loads(completed.stdout)
    assert payload == {
        "status": "BLOCKED",
        "code": "CONFIG_MISSING",
        "missing": ["WECHAT_MP_APP_ID", "WECHAT_MP_APP_SECRET"],
        "delivery_verified": False,
    }
    assert completed.stderr == ""


def test_cli_draft_without_cover_returns_structured_blocked_before_network(tmp_path):
    completed = _run_cli(
        tmp_path,
        "draft",
        include_cover=False,
        extra_env={
            "WECHAT_CREDENTIAL_SOURCE": "environment",
            "WECHAT_MP_APP_ID": "wx-test",
            "WECHAT_MP_APP_SECRET": "secret-not-for-output",
        },
    )

    assert completed.returncode == 2
    payload = json.loads(completed.stdout)
    assert payload["status"] == "BLOCKED"
    assert payload["code"] == "THUMB_MEDIA_ID_MISSING"
    assert "secret-not-for-output" not in completed.stdout
    assert completed.stderr == ""


def test_cli_draft_reports_staging_success_even_when_public_delivery_awaits_approval(
    tmp_path, monkeypatch, capsys
):
    from scripts import run_daily_wechat as cli

    issue_path = tmp_path / "issue.json"
    _write_issue(issue_path)

    class DraftOnlyClient:
        def __init__(self, app_id, app_secret):
            assert app_id == "wx-test"
            assert app_secret == "secret-not-for-output"

        def add_draft(self, article):
            return {"media_id": "draft-id"}

    monkeypatch.setattr(cli, "WeChatApiClient", DraftOnlyClient)
    result = cli.main(
        [
            "--content",
            str(issue_path),
            "--action",
            "draft",
            "--ledger",
            str(tmp_path / "runtime" / "ledger.sqlite3"),
        ],
        environment={
            "WECHAT_CREDENTIAL_SOURCE": "environment",
            "WECHAT_MP_APP_ID": "wx-test",
            "WECHAT_MP_APP_SECRET": "secret-not-for-output",
            "WECHAT_RUNTIME_DIR": str(tmp_path / "runtime"),
        },
    )

    payload = json.loads(capsys.readouterr().out)
    assert result == 0
    assert payload["status"] == "DRAFT_STAGED"
    assert payload["state"] == "pending_approval"
    assert payload["delivery_verified"] is False


def test_cli_defaults_to_dpapi_vault_instead_of_environment_secrets(monkeypatch):
    from scripts import run_daily_wechat as cli

    class FakeVault:
        def load(self):
            return {"app_id": "vault-app", "app_secret": "vault-secret"}

    monkeypatch.setattr(cli, "WechatCredentialVault", FakeVault)

    credentials = cli._load_runtime_credentials(
        {
            "WECHAT_MP_APP_ID": "environment-app",
            "WECHAT_MP_APP_SECRET": "environment-secret",
        }
    )

    assert credentials == {"app_id": "vault-app", "app_secret": "vault-secret"}


def test_cli_reads_secret_store_environment_only_with_explicit_cloud_opt_in(monkeypatch):
    from scripts import run_daily_wechat as cli

    class EmptyVault:
        def load(self):
            return None

    monkeypatch.setattr(cli, "WechatCredentialVault", EmptyVault)
    environment = {
        "WECHAT_CREDENTIAL_SOURCE": "environment",
        "WECHAT_MP_APP_ID": "cloud-app",
        "WECHAT_MP_APP_SECRET": "cloud-secret",
        "WECHAT_THUMB_MEDIA_ID": "cloud-cover",
        "WECHAT_APPROVAL_PUBLIC_KEY": APPROVAL_PUBLIC_KEY_PEM,
    }

    assert cli._load_runtime_credentials(environment) == {
        "app_id": "cloud-app",
        "app_secret": "cloud-secret",
        "thumb_media_id": "cloud-cover",
        "approval_public_key": APPROVAL_PUBLIC_KEY_PEM,
    }


def test_draft_can_resolve_a_prepare_cover_blocker_from_the_vault(
    tmp_path, monkeypatch, capsys
):
    from scripts import run_daily_wechat as cli

    issue_path = tmp_path / "issue.json"
    ledger_path = tmp_path / "runtime" / "ledger.sqlite3"
    _write_issue(issue_path, include_cover=False)
    common_args = [
        "--content",
        str(issue_path),
        "--ledger",
        str(ledger_path),
    ]
    environment = {"WECHAT_RUNTIME_DIR": str(tmp_path / "runtime")}
    assert cli.main([*common_args, "--action", "prepare"], environment=environment) == 0
    assert json.loads(capsys.readouterr().out)["blockers"] == ["THUMB_MEDIA_ID_MISSING"]

    class FakeVault:
        def __init__(self, path=None):
            self.path = path

        def load(self):
            return {
                "app_id": "vault-app",
                "app_secret": "vault-secret",
                "thumb_media_id": "vault-cover",
            }

    class DraftOnlyClient:
        def __init__(self, app_id, app_secret):
            assert (app_id, app_secret) == ("vault-app", "vault-secret")

        def add_draft(self, article):
            assert article["thumb_media_id"] == "vault-cover"
            return {"media_id": "draft-id"}

    monkeypatch.setattr(cli, "WechatCredentialVault", FakeVault)
    monkeypatch.setattr(cli, "WeChatApiClient", DraftOnlyClient)

    assert cli.main([*common_args, "--action", "draft"], environment=environment) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "DRAFT_STAGED"
    assert payload["draft_media_id"] == "draft-id"


def test_interactive_configurator_never_echoes_credentials(
    tmp_path, monkeypatch, capsys
):
    from scripts import configure_wechat_mp as configure

    entered = iter(
        [
            "wx-configured-app",
            "configured-app-secret",
            "configured-cover-id",
        ]
    )
    public_key_path = tmp_path / "approval-public.pem"
    public_key_path.write_text(APPROVAL_PUBLIC_KEY_PEM, encoding="ascii")
    saved = {}

    events = []

    class FakeVault:
        def __init__(self, path=None):
            self.path = path or os.path.join("config", ".wechat_mp.vault")

        def save(self, credentials):
            assert events == ["secured"]
            saved.update(credentials)

    monkeypatch.setattr(configure, "WechatCredentialVault", FakeVault)
    monkeypatch.setattr(configure.getpass, "getpass", lambda prompt: next(entered))
    monkeypatch.setattr(
        configure,
        "ensure_secure_directory",
        lambda path: events.append("secured"),
        raising=False,
    )
    monkeypatch.setenv("WECHAT_RUNTIME_DIR", str(tmp_path / "runtime"))

    assert configure.main(["--approval-public-key-file", str(public_key_path)]) == 0
    output = capsys.readouterr()

    assert saved == {
        "app_id": "wx-configured-app",
        "app_secret": "configured-app-secret",
        "thumb_media_id": "configured-cover-id",
        "approval_public_key": APPROVAL_PUBLIC_KEY_PEM,
    }
    assert json.loads(output.out)["status"] == "CONFIGURED"
    assert "wx-configured-app" not in output.out
    assert "configured-app-secret" not in output.out
    assert "configured-cover-id" not in output.out
    assert "BEGIN PUBLIC KEY" not in output.out
    assert output.err == ""


def test_interactive_configurator_reports_runtime_file_security_failure(
    tmp_path, monkeypatch, capsys
):
    from scripts import configure_wechat_mp as configure

    entered = iter(["wx-app", "app-secret", "cover-id"])

    class FailingVault:
        def __init__(self, path=None):
            self.path = path

        def save(self, credentials):
            raise configure.RuntimeSecurityError("mode verification failed")

    monkeypatch.setattr(configure, "WechatCredentialVault", FailingVault)
    monkeypatch.setattr(configure.getpass, "getpass", lambda prompt: next(entered))
    monkeypatch.setattr(configure, "ensure_secure_directory", lambda path: None)
    monkeypatch.setenv("WECHAT_RUNTIME_DIR", str(tmp_path / "runtime"))

    assert configure.main([]) == 2
    assert json.loads(capsys.readouterr().out) == {
        "status": "BLOCKED",
        "code": "RUNTIME_SECURITY_ERROR",
    }


def test_gui_configurator_secures_runtime_and_saves_without_echoing_secrets(
    tmp_path, monkeypatch, capsys
):
    from scripts import configure_wechat_mp_gui as configure

    runtime_dir = tmp_path / "private-runtime"
    vault_path = runtime_dir / ".wechat_mp.vault"
    events = []
    notifications = []
    saved = {}

    class FakeVault:
        def __init__(self, path):
            assert path == vault_path
            events.append("vault")

        def save(self, credentials):
            assert events == ["secured", "prompted", "vault"]
            saved.update(credentials)

    monkeypatch.setattr(
        configure,
        "resolve_runtime_paths",
        lambda environment=None: SimpleNamespace(
            runtime_dir=runtime_dir,
            vault_path=vault_path,
        ),
    )
    monkeypatch.setattr(
        configure,
        "ensure_secure_directory",
        lambda path: events.append("secured") if path == runtime_dir else None,
    )

    secrets = {
        "app_id": "wx-gui-app",
        "app_secret": "gui-app-secret",
        "thumb_media_id": "gui-cover-id",
    }

    def prompt():
        assert events == ["secured"]
        events.append("prompted")
        return dict(secrets)

    result = configure.main(
        [],
        prompt=prompt,
        message=lambda status, code: notifications.append((status, code)),
        vault_factory=FakeVault,
        environment={
            "WECHAT_MP_APP_ID": "must-not-be-read",
            "WECHAT_MP_APP_SECRET": "must-not-be-read",
            "WECHAT_MP_THUMB_MEDIA_ID": "must-not-be-read",
        },
    )

    output = capsys.readouterr()
    assert result == 0
    assert saved == secrets
    assert notifications == [("CONFIGURED", "CONFIGURED")]
    assert output.out.strip() == "CONFIGURED"
    assert output.err == ""
    for secret in (*secrets.values(), str(runtime_dir), str(vault_path)):
        assert secret not in output.out
        assert secret not in output.err


@pytest.mark.parametrize(
    "credentials",
    [
        {"app_id": "", "app_secret": "secret", "thumb_media_id": "cover"},
        {"app_id": "app", "app_secret": "  ", "thumb_media_id": "cover"},
        {"app_id": "app", "app_secret": "secret", "thumb_media_id": "\t"},
    ],
)
def test_gui_configurator_rejects_empty_fields_without_opening_vault(
    tmp_path, monkeypatch, capsys, credentials
):
    from scripts import configure_wechat_mp_gui as configure

    class NeverVault:
        def __init__(self, path):
            raise AssertionError("vault must not be opened for missing input")

    monkeypatch.setattr(
        configure,
        "resolve_runtime_paths",
        lambda environment=None: SimpleNamespace(
            runtime_dir=tmp_path / "runtime",
            vault_path=tmp_path / "runtime" / ".wechat_mp.vault",
        ),
    )
    monkeypatch.setattr(configure, "ensure_secure_directory", lambda path: None)
    notifications = []

    result = configure.main(
        [],
        prompt=lambda: dict(credentials),
        message=lambda status, code: notifications.append((status, code)),
        vault_factory=NeverVault,
        environment={
            "WECHAT_MP_APP_ID": "env-app-must-not-fill-empty-input",
            "WECHAT_MP_APP_SECRET": "env-secret-must-not-fill-empty-input",
        },
    )

    assert result == 2
    assert notifications == [("BLOCKED", "INPUT_MISSING")]
    assert capsys.readouterr().out.strip() == "INPUT_MISSING"


def test_gui_configurator_fails_closed_with_stable_safe_codes(
    tmp_path, monkeypatch, capsys
):
    from scripts import configure_wechat_mp_gui as configure

    notifications = []

    def reject_runtime(environment=None):
        raise configure.RuntimeSecurityError(
            f"unsafe secret location {tmp_path / 'private-details'}"
        )

    monkeypatch.setattr(configure, "resolve_runtime_paths", reject_runtime)

    result = configure.main(
        [],
        prompt=lambda: (_ for _ in ()).throw(
            AssertionError("prompt must not open after runtime failure")
        ),
        message=lambda status, code: notifications.append((status, code)),
        environment={},
    )

    captured = capsys.readouterr()
    assert result == 2
    assert notifications == [("BLOCKED", "RUNTIME_SECURITY_ERROR")]
    assert captured.out.strip() == "RUNTIME_SECURITY_ERROR"
    assert str(tmp_path) not in captured.out
    assert captured.err == ""


def test_gui_configurator_rejects_arguments_before_prompt_or_vault(capsys):
    from scripts import configure_wechat_mp_gui as configure

    notifications = []
    result = configure.main(
        ["--app-secret", "must-never-be-accepted"],
        prompt=lambda: (_ for _ in ()).throw(AssertionError("prompt must not open")),
        message=lambda status, code: notifications.append((status, code)),
        vault_factory=lambda path: (_ for _ in ()).throw(
            AssertionError("vault must not open")
        ),
        environment={},
    )

    captured = capsys.readouterr()
    assert result == 2
    assert notifications == [("BLOCKED", "ARGUMENTS_NOT_ALLOWED")]
    assert captured.out.strip() == "ARGUMENTS_NOT_ALLOWED"
    assert "must-never-be-accepted" not in captured.out
    assert captured.err == ""


def test_tk_prompt_masks_all_three_fields_and_returns_them_in_order():
    from scripts import configure_wechat_mp_gui as configure

    entries = []
    buttons = []

    class FakeRoot:
        def title(self, value):
            assert value == "公众号安全配置"

        def resizable(self, width, height):
            assert (width, height) == (False, False)

        def protocol(self, name, callback):
            assert name == "WM_DELETE_WINDOW"
            self.cancel = callback

        def mainloop(self):
            values = iter(["wx-visible-app", "visible-secret", "visible-cover"])
            for entry in entries:
                entry.variable.set(next(values))
            next(button for button in buttons if button.text == "安全保存").command()

        def destroy(self):
            pass

    class FakeStringVar:
        def __init__(self, master=None):
            self.value = ""

        def set(self, value):
            self.value = value

        def get(self):
            return self.value

    class FakeWidget:
        def __init__(self, parent=None, **kwargs):
            self.parent = parent
            self.kwargs = kwargs

        def grid(self, **kwargs):
            self.grid_options = kwargs
            return self

    class FakeEntry(FakeWidget):
        def __init__(self, parent=None, **kwargs):
            super().__init__(parent, **kwargs)
            self.variable = kwargs["textvariable"]
            entries.append(self)

        def focus_set(self):
            pass

    class FakeButton(FakeWidget):
        def __init__(self, parent=None, **kwargs):
            super().__init__(parent, **kwargs)
            self.text = kwargs["text"]
            self.command = kwargs["command"]
            buttons.append(self)

    fake_tk = SimpleNamespace(
        Tk=FakeRoot,
        StringVar=FakeStringVar,
        Label=FakeWidget,
        Entry=FakeEntry,
        Button=FakeButton,
    )

    result = configure.prompt_credentials(tk_module=fake_tk)

    assert [entry.kwargs["show"] for entry in entries] == ["*", "*", "*"]
    assert result == {
        "app_id": "wx-visible-app",
        "app_secret": "visible-secret",
        "thumb_media_id": "visible-cover",
    }


@pytest.mark.parametrize(
    ("error_factory", "expected_code"),
    [
        (
            lambda configure, detail: configure.CredentialVaultError(detail),
            "CREDENTIAL_VAULT_ERROR",
        ),
        (
            lambda configure, detail: configure.RuntimeSecurityError(detail),
            "RUNTIME_SECURITY_ERROR",
        ),
    ],
)
def test_gui_configurator_sanitizes_vault_failures(
    tmp_path, monkeypatch, capsys, error_factory, expected_code
):
    from scripts import configure_wechat_mp_gui as configure

    runtime_dir = tmp_path / "runtime"
    secret = "vault-failure-secret"
    notifications = []

    class FailingVault:
        def __init__(self, path):
            self.path = path

        def save(self, credentials):
            raise error_factory(configure, f"{secret} at {self.path}")

    monkeypatch.setattr(
        configure,
        "resolve_runtime_paths",
        lambda environment=None: SimpleNamespace(
            runtime_dir=runtime_dir,
            vault_path=runtime_dir / ".wechat_mp.vault",
        ),
    )
    monkeypatch.setattr(configure, "ensure_secure_directory", lambda path: None)

    result = configure.main(
        [],
        prompt=lambda: {
            "app_id": "wx-app",
            "app_secret": secret,
            "thumb_media_id": "cover",
        },
        message=lambda status, code: notifications.append((status, code)),
        vault_factory=FailingVault,
        environment={},
    )

    captured = capsys.readouterr()
    assert result == 2
    assert notifications == [("BLOCKED", expected_code)]
    assert captured.out.strip() == expected_code
    assert secret not in captured.out
    assert str(runtime_dir) not in captured.out
    assert captured.err == ""


def test_gui_completion_popups_use_only_fixed_safe_text(monkeypatch, tmp_path):
    from scripts import configure_wechat_mp_gui as configure

    calls = []
    messagebox = SimpleNamespace(
        showinfo=lambda title, body: calls.append(("info", title, body)),
        showerror=lambda title, body: calls.append(("error", title, body)),
    )
    tkinter_module = ModuleType("tkinter")
    tkinter_module.messagebox = messagebox
    monkeypatch.setitem(sys.modules, "tkinter", tkinter_module)

    for code in configure._SAFE_MESSAGES:
        status = "CONFIGURED" if code == "CONFIGURED" else "BLOCKED"
        configure.show_message(status, code)

    unsafe_fragments = (
        "popup-secret",
        str(tmp_path),
        "AppSecret",
        "media_id",
    )
    assert len(calls) == len(configure._SAFE_MESSAGES)
    assert calls[0] == (
        "info",
        "公众号安全配置",
        "配置已安全保存",
    )
    assert all(kind == "error" for kind, _title, _body in calls[1:])
    rendered = "\n".join(" ".join(call) for call in calls)
    assert all(fragment not in rendered for fragment in unsafe_fragments)


def test_cli_can_run_from_an_arbitrary_working_directory(tmp_path):
    issue_path = tmp_path / "issue.json"
    _write_issue(issue_path)
    script = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "scripts", "run_daily_wechat.py"
    )
    env = os.environ.copy()
    for name in (
        "WECHAT_MP_APP_ID",
        "WECHAT_MP_APP_SECRET",
        "WECHAT_APPROVAL_PUBLIC_KEY",
        "WECHAT_THUMB_MEDIA_ID",
        "WECHAT_CREDENTIAL_SOURCE",
        "WECHAT_RUNTIME_DIR",
        "WECHAT_LEDGER_PATH",
    ):
        env.pop(name, None)
    env["WECHAT_RUNTIME_DIR"] = str(tmp_path / "runtime")
    completed = subprocess.run(
        [
            sys.executable,
            script,
            "--content",
            str(issue_path),
            "--action",
            "prepare",
            "--ledger",
            str(tmp_path / "runtime" / "ledger.sqlite3"),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["status"] == "REVIEW_PENDING"


def test_runtime_paths_default_to_private_user_data_not_repo(tmp_path):
    from scripts import run_daily_wechat as cli

    paths = cli.resolve_runtime_paths(
        {"LOCALAPPDATA": str(tmp_path / "local")},
        platform_name="nt",
    )

    assert paths.runtime_dir == tmp_path / "local" / "DefenseTracker" / "wechat"
    assert paths.vault_path == paths.runtime_dir / ".wechat_mp.vault"
    assert paths.ledger_path == paths.runtime_dir / "wechat_publications.sqlite3"
    assert cli.REPO_ROOT not in paths.ledger_path.parents


def test_runtime_paths_honor_explicit_runtime_and_ledger_overrides(tmp_path):
    from scripts import run_daily_wechat as cli

    environment = {
        "WECHAT_RUNTIME_DIR": str(tmp_path / "runtime-explicit"),
        "WECHAT_LEDGER_PATH": str(tmp_path / "env-ledger.sqlite3"),
    }
    env_paths = cli.resolve_runtime_paths(environment, platform_name="nt")
    cli_paths = cli.resolve_runtime_paths(
        environment,
        ledger_override=tmp_path / "cli-ledger.sqlite3",
        platform_name="nt",
    )

    assert env_paths.runtime_dir == tmp_path / "runtime-explicit"
    assert env_paths.ledger_path == tmp_path / "env-ledger.sqlite3"
    assert cli_paths.ledger_path == tmp_path / "cli-ledger.sqlite3"
    assert env_paths.vault_path == tmp_path / "runtime-explicit" / ".wechat_mp.vault"


def test_non_windows_runtime_default_uses_user_data_home(tmp_path):
    from scripts import run_daily_wechat as cli

    paths = cli.resolve_runtime_paths(
        {},
        platform_name="posix",
        home=tmp_path / "home",
    )

    assert paths.runtime_dir == (
        tmp_path / "home" / ".local" / "share" / "DefenseTracker" / "wechat"
    )
    assert cli.REPO_ROOT not in paths.runtime_dir.parents


def test_non_windows_runtime_permissions_are_0700_and_files_are_0600(tmp_path):
    from scripts import run_daily_wechat as cli

    runtime_dir = tmp_path / "runtime"
    applied_modes = {}

    def set_mode(path, mode):
        applied_modes[os.fspath(path)] = mode

    def read_mode(path):
        return applied_modes[os.fspath(path)]

    cli.ensure_secure_directory(
        runtime_dir,
        platform_name="posix",
        chmod_func=set_mode,
        mode_reader=read_mode,
    )
    private_file = runtime_dir / "ledger.sqlite3"
    private_file.write_text("private", encoding="utf-8")
    cli.ensure_private_file(
        private_file,
        platform_name="posix",
        chmod_func=set_mode,
        mode_reader=read_mode,
    )

    assert applied_modes[os.fspath(runtime_dir)] == 0o700
    assert applied_modes[os.fspath(private_file)] == 0o600


def test_windows_acl_validation_fails_closed_on_unexpected_principal(tmp_path):
    from scripts import run_daily_wechat as cli

    current_sid = "S-1-5-21-1000"
    calls = []

    def fake_runner(argv, **kwargs):
        calls.append((argv, kwargs))
        assert isinstance(argv, list)
        assert kwargs.get("shell", False) is False
        if str(argv[0]).lower().endswith("icacls.exe"):
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "protected": True,
                    "entries": [
                        {"sid": current_sid, "type": "Allow", "rights": "FullControl"},
                        {"sid": "S-1-5-18", "type": "Allow", "rights": "FullControl"},
                        {
                            "sid": "S-1-5-32-544",
                            "type": "Allow",
                            "rights": "FullControl",
                        },
                        {
                            "sid": "S-1-5-32-545",
                            "type": "Allow",
                            "rights": "ReadAndExecute",
                        },
                    ],
                }
            ),
            stderr="",
        )

    with pytest.raises(cli.RuntimeSecurityError):
        cli.ensure_secure_directory(
            tmp_path / "runtime",
            platform_name="nt",
            runner=fake_runner,
            current_user_sid=current_sid,
        )

    assert any(str(call[0][0]).lower().endswith("icacls.exe") for call in calls)


def test_existing_explicit_ledger_parent_is_validated_without_acl_mutation(
    tmp_path, monkeypatch, capsys
):
    from scripts import run_daily_wechat as cli

    issue_path = tmp_path / "issue.json"
    runtime_dir = tmp_path / "runtime"
    shared_parent = tmp_path / "already-private"
    shared_parent.mkdir()
    _write_issue(issue_path)
    secured = []
    validated = []

    class EmptyVault:
        def __init__(self, path=None):
            self.path = path

        def load(self):
            return None

    def record_secure(path, *args, **kwargs):
        secured.append(os.fspath(path))

    def record_validation(path, *args, **kwargs):
        validated.append(os.fspath(path))

    monkeypatch.setattr(cli, "WechatCredentialVault", EmptyVault)
    monkeypatch.setattr(cli, "ensure_secure_directory", record_secure)
    monkeypatch.setattr(
        cli,
        "validate_secure_directory",
        record_validation,
        raising=False,
    )

    result = cli.main(
        [
            "--content",
            str(issue_path),
            "--action",
            "prepare",
            "--ledger",
            str(shared_parent / "ledger.sqlite3"),
        ],
        environment={"WECHAT_RUNTIME_DIR": str(runtime_dir)},
    )

    assert result == 0, capsys.readouterr().out
    assert secured == [os.fspath(runtime_dir)]
    assert validated == [os.fspath(shared_parent)]


def test_existing_windows_ledger_parent_validation_never_calls_icacls(tmp_path):
    from scripts import run_daily_wechat as cli

    current_sid = "S-1-5-21-1000"
    calls = []

    def fake_runner(argv, **kwargs):
        calls.append(list(argv))
        if str(argv[0]).lower().endswith("icacls.exe"):
            raise AssertionError("read-only validation must not call icacls")
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "protected": True,
                    "entries": [
                        {"sid": current_sid, "type": "Allow", "rights": "FullControl"},
                        {"sid": "S-1-5-18", "type": "Allow", "rights": "FullControl"},
                        {
                            "sid": "S-1-5-32-544",
                            "type": "Allow",
                            "rights": "FullControl",
                        },
                    ],
                }
            ),
            stderr="",
        )

    cli.validate_secure_directory(
        tmp_path,
        platform_name="nt",
        runner=fake_runner,
        current_user_sid=current_sid,
    )

    assert calls
    assert all(not str(argv[0]).lower().endswith("icacls.exe") for argv in calls)


def test_missing_explicit_ledger_parent_creates_only_one_dedicated_leaf(tmp_path):
    from scripts import run_daily_wechat as cli

    missing_grandparent = tmp_path / "missing" / "dedicated"

    with pytest.raises(cli.RuntimeSecurityError):
        cli.prepare_secure_ledger_directory(
            missing_grandparent,
            platform_name="posix",
        )

    assert not (tmp_path / "missing").exists()


def test_windows_leaf_junction_blocks_before_acl_or_directory_creation(tmp_path):
    from scripts import run_daily_wechat as cli

    target = tmp_path / "runtime-junction"
    permission_calls = []

    with pytest.raises(cli.RuntimeSecurityError):
        cli.ensure_secure_directory(
            target,
            platform_name="nt",
            runner=lambda *args, **kwargs: permission_calls.append((args, kwargs)),
            junction_checker=lambda candidate: candidate == target,
            lstat_func=lambda candidate: SimpleNamespace(st_file_attributes=0),
        )

    assert permission_calls == []
    assert not target.exists()


def test_windows_ancestor_reparse_point_blocks_before_acl_or_chmod(tmp_path):
    from scripts import run_daily_wechat as cli

    ancestor = tmp_path / "junction-parent"
    target = ancestor / "runtime"
    permission_calls = []

    def fake_lstat(candidate):
        attributes = 0x400 if candidate == ancestor else 0
        return SimpleNamespace(st_file_attributes=attributes)

    with pytest.raises(cli.RuntimeSecurityError):
        cli.ensure_secure_directory(
            target,
            platform_name="nt",
            runner=lambda *args, **kwargs: permission_calls.append((args, kwargs)),
            junction_checker=lambda candidate: False,
            lstat_func=fake_lstat,
        )

    assert permission_calls == []
    assert not target.exists()


def test_windows_private_file_acl_is_set_and_exactly_validated(tmp_path):
    from scripts import run_daily_wechat as cli

    private_file = tmp_path / "wechat.sqlite3"
    private_file.write_bytes(b"sqlite")
    current_sid = "S-1-5-21-1000"
    calls = []

    def fake_runner(argv, **kwargs):
        calls.append((list(argv), kwargs))
        if str(argv[0]).lower().endswith("powershell.exe"):
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    {
                        "protected": True,
                        "entries": [
                            {
                                "sid": current_sid,
                                "type": "Allow",
                                "rights": "FullControl",
                            },
                            {
                                "sid": "S-1-5-18",
                                "type": "Allow",
                                "rights": "FullControl",
                            },
                            {
                                "sid": "S-1-5-32-544",
                                "type": "Allow",
                                "rights": "FullControl",
                            },
                        ],
                    }
                ),
                stderr="",
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    cli.ensure_private_file(
        private_file,
        platform_name="nt",
        runner=fake_runner,
        current_user_sid=current_sid,
        junction_checker=lambda candidate: False,
        lstat_func=lambda candidate: SimpleNamespace(st_file_attributes=0),
    )

    icacls_calls = [
        argv for argv, _ in calls if str(argv[0]).lower().endswith("icacls.exe")
    ]
    assert icacls_calls
    assert any("/inheritance:r" in argv for argv in icacls_calls)
    assert all("(OI)(CI)" not in argument for argv in icacls_calls for argument in argv)


def test_windows_private_file_reparse_blocks_before_acl(tmp_path):
    from scripts import run_daily_wechat as cli

    private_file = tmp_path / "vault-link"
    private_file.write_bytes(b"protected")
    permission_calls = []

    with pytest.raises(cli.RuntimeSecurityError):
        cli.ensure_private_file(
            private_file,
            platform_name="nt",
            runner=lambda *args, **kwargs: permission_calls.append((args, kwargs)),
            junction_checker=lambda candidate: candidate == private_file,
            lstat_func=lambda candidate: SimpleNamespace(st_file_attributes=0),
        )

    assert permission_calls == []


def test_legacy_ledger_copy_is_row_verified_and_keeps_source(tmp_path):
    from scripts import run_daily_wechat as cli

    source = tmp_path / "legacy" / "wechat_publications.sqlite3"
    destination = tmp_path / "runtime" / "wechat_publications.sqlite3"
    manifest = _manifest(delivery="publish")
    legacy = PublicationLedger(source)
    legacy.reserve(manifest)
    legacy.update(
        manifest,
        state="published",
        draft_media_id="draft-remote-id",
        publish_id="publish-remote-id",
        msg_id="message-remote-id",
        clientmsgid="client-remote-id",
        result_json='{"remote":"verified"}',
        operation_owner="worker-id",
        operation_kind="publish",
        lease_until=12345.0,
    )

    assert cli.migrate_legacy_ledger(source, destination) is True

    assert source.is_file()
    migrated = PublicationLedger(destination).get(
        manifest["channel"], manifest["publication_date"], manifest["edition"]
    )
    original = legacy.get(
        manifest["channel"], manifest["publication_date"], manifest["edition"]
    )
    for field in (
        "channel",
        "publication_date",
        "edition",
        "content_sha256",
        "source_sha256",
        "state",
        "draft_media_id",
        "publish_id",
        "msg_id",
        "clientmsgid",
        "result_json",
        "operation_owner",
        "operation_kind",
        "lease_until",
        "created_at",
        "updated_at",
    ):
        assert migrated[field] == original[field]


def test_legacy_ledger_migration_removes_incomplete_copy_on_mismatch(tmp_path):
    from scripts import run_daily_wechat as cli

    source = tmp_path / "legacy" / "wechat_publications.sqlite3"
    destination = tmp_path / "runtime" / "wechat_publications.sqlite3"
    manifest = _manifest()
    PublicationLedger(source).reserve(manifest)

    def corrupting_copier(source_path, destination_path):
        shutil.copy2(source_path, destination_path)
        connection = sqlite3.connect(destination_path)
        try:
            connection.execute(
                "UPDATE publications SET result_json=?",
                ('{"tampered":true}',),
            )
            connection.commit()
        finally:
            connection.close()

    with pytest.raises(cli.LedgerMigrationError):
        cli.migrate_legacy_ledger(source, destination, copier=corrupting_copier)

    assert source.is_file()
    assert not destination.exists()
    assert not list(destination.parent.glob("*.migration-*.tmp"))


def _create_malformed_publication_ledger(
    path, *, primary_key, content_sha256_declaration="TEXT NOT NULL", duplicate=False
):
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            f"""
            CREATE TABLE publications (
                channel TEXT NOT NULL,
                publication_date TEXT NOT NULL,
                edition TEXT NOT NULL,
                content_sha256 {content_sha256_declaration},
                source_sha256 TEXT NOT NULL,
                state TEXT NOT NULL,
                draft_media_id TEXT,
                publish_id TEXT,
                msg_id TEXT,
                clientmsgid TEXT,
                result_json TEXT,
                operation_owner TEXT,
                operation_kind TEXT,
                lease_until REAL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
                {',' if primary_key else ''} {primary_key}
            )
            """
        )
        row = (
            "wechat_official",
            "2026-08-14",
            "daily",
            "a" * 64,
            "b" * 64,
            "review_pending",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            "2026-08-14T00:00:00+08:00",
            "2026-08-14T00:00:00+08:00",
        )
        placeholders = ",".join("?" for _ in row)
        connection.execute(f"INSERT INTO publications VALUES ({placeholders})", row)
        if duplicate:
            connection.execute(f"INSERT INTO publications VALUES ({placeholders})", row)
        connection.commit()
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("primary_key", "content_declaration", "duplicate"),
    [
        (
            "PRIMARY KEY (edition, publication_date, channel)",
            "TEXT NOT NULL",
            False,
        ),
        (
            "PRIMARY KEY (channel, publication_date, edition)",
            "BLOB NOT NULL",
            False,
        ),
        ("", "TEXT NOT NULL", True),
    ],
    ids=("wrong-pk-ordinal", "wrong-required-type", "duplicate-key"),
)
def test_legacy_ledger_migration_rejects_malformed_schema_and_duplicate_keys(
    tmp_path, primary_key, content_declaration, duplicate
):
    from scripts import run_daily_wechat as cli

    source = tmp_path / "legacy" / "wechat_publications.sqlite3"
    destination = tmp_path / "runtime" / "wechat_publications.sqlite3"
    _create_malformed_publication_ledger(
        source,
        primary_key=primary_key,
        content_sha256_declaration=content_declaration,
        duplicate=duplicate,
    )

    with pytest.raises(cli.LedgerMigrationError):
        cli.migrate_legacy_ledger(source, destination)

    assert source.is_file()
    assert not destination.exists()


def test_legacy_ledger_migration_existing_lock_fails_closed(tmp_path):
    from scripts import run_daily_wechat as cli

    source = tmp_path / "legacy" / "wechat_publications.sqlite3"
    destination = tmp_path / "runtime" / "wechat_publications.sqlite3"
    PublicationLedger(source).reserve(_manifest())
    cli.ensure_secure_directory(destination.parent)
    lock_path = destination.with_name(f"{destination.name}.migration.lock")
    lock_path.write_text("other process", encoding="utf-8")

    with pytest.raises(cli.LedgerMigrationError):
        cli.migrate_legacy_ledger(source, destination)

    assert source.is_file()
    assert lock_path.read_text(encoding="utf-8") == "other process"
    assert not destination.exists()


def test_legacy_ledger_migration_never_clobbers_destination_that_appears(tmp_path):
    from scripts import run_daily_wechat as cli

    source = tmp_path / "legacy" / "wechat_publications.sqlite3"
    destination = tmp_path / "runtime" / "wechat_publications.sqlite3"
    PublicationLedger(source).reserve(_manifest())
    external_bytes = b"external-ledger-won-race"

    def destination_appears_linker(source_path, destination_path):
        destination_path.write_bytes(external_bytes)
        raise FileExistsError(destination_path)

    with pytest.raises(cli.LedgerMigrationError):
        cli.migrate_legacy_ledger(
            source,
            destination,
            linker=destination_appears_linker,
        )

    assert destination.read_bytes() == external_bytes
    assert source.is_file()


def test_prepare_injects_vault_cover_without_client_or_issue_mutation(
    tmp_path, monkeypatch, capsys
):
    from scripts import run_daily_wechat as cli

    issue_path = tmp_path / "issue.json"
    ledger_path = tmp_path / "runtime" / "ledger.sqlite3"
    _write_issue(issue_path, include_cover=False)
    original_issue = issue_path.read_bytes()

    class FakeVault:
        def __init__(self, path=None):
            self.path = path

        def load(self):
            return {
                "app_id": "vault-app",
                "app_secret": "vault-secret",
                "thumb_media_id": "vault-cover",
            }

    class NeverClient:
        def __init__(self, *args, **kwargs):
            raise AssertionError("prepare must not construct a WeChat client")

    monkeypatch.setattr(cli, "WechatCredentialVault", FakeVault)
    monkeypatch.setattr(cli, "WeChatApiClient", NeverClient)
    monkeypatch.setattr(cli, "ensure_secure_directory", lambda *args, **kwargs: None)

    result = cli.main(
        [
            "--content",
            str(issue_path),
            "--action",
            "prepare",
            "--ledger",
            str(ledger_path),
        ],
        environment={"WECHAT_RUNTIME_DIR": str(tmp_path / "runtime")},
    )

    payload = json.loads(capsys.readouterr().out)
    expected_manifest = cli.issue_to_manifest(
        json.loads(issue_path.read_text(encoding="utf-8")), "prepare", {}
    )
    expected_manifest["article"]["thumb_media_id"] = "vault-cover"
    assert result == 0
    assert payload["blockers"] == []
    assert payload["content_sha256"] == compute_manifest_hashes(expected_manifest)[
        "content_sha256"
    ]
    assert issue_path.read_bytes() == original_issue
    assert PublicationLedger(ledger_path).get("wechat_official", "2026-08-14", "daily")[
        "content_sha256"
    ] == payload["content_sha256"]


def test_prepare_corrupt_vault_blocks_before_ledger_write(tmp_path, monkeypatch, capsys):
    from scripts import run_daily_wechat as cli

    issue_path = tmp_path / "issue.json"
    ledger_path = tmp_path / "runtime" / "ledger.sqlite3"
    _write_issue(issue_path, include_cover=False)

    class CorruptVault:
        def __init__(self, path=None):
            self.path = path

        def load(self):
            raise cli.CredentialVaultError("corrupt")

    class NeverClient:
        def __init__(self, *args, **kwargs):
            raise AssertionError("prepare must not construct a WeChat client")

    monkeypatch.setattr(cli, "WechatCredentialVault", CorruptVault)
    monkeypatch.setattr(cli, "WeChatApiClient", NeverClient)
    monkeypatch.setattr(cli, "ensure_secure_directory", lambda *args, **kwargs: None)

    result = cli.main(
        [
            "--content",
            str(issue_path),
            "--action",
            "prepare",
            "--ledger",
            str(ledger_path),
        ],
        environment={"WECHAT_RUNTIME_DIR": str(tmp_path / "runtime")},
    )

    assert result == 2
    assert json.loads(capsys.readouterr().out) == {
        "status": "BLOCKED",
        "code": "CREDENTIAL_VAULT_ERROR",
        "delivery_verified": False,
    }
    assert not ledger_path.exists()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("title", "防" * 33),
        ("digest", "摘" * 121),
    ],
)
def test_preflight_rejects_wechat_length_violations_before_network(
    tmp_path, field, value
):
    manifest = _manifest()
    manifest["article"][field] = value
    service, session = _service(tmp_path, [])

    with pytest.raises(ManifestError):
        service.run(manifest)

    assert session.calls == []


@pytest.mark.parametrize(
    "content",
    [
        "<script>alert(1)</script>",
        "<iframe src='https://example.org'></iframe>",
        "<form><input></form>",
        "<object data='x'></object>",
        "<embed src='x'>",
        "<p onclick='run()'>正文</p>",
        "<img src='file:///C:/private/cover.png'>",
        r"<p>C:" + r"\Users\name\private.txt</p>",
        r"<p>\\server\share\private.txt</p>",
    ],
)
def test_preflight_rejects_active_html_and_local_paths_before_network(tmp_path, content):
    service, session = _service(tmp_path, [])

    with pytest.raises(ManifestError):
        service.run(_manifest(content=content))

    assert session.calls == []


@pytest.mark.parametrize(
    "content",
    [
        '<a href="javascript:alert(1)">x</a>',
        '<a href="jav&#x61;script:alert(1)">x</a>',
        '<img src="data:text/html,<script>alert(1)</script>">',
        '<p style="background:url(javascript:alert(1))">x</p>',
        '<img src="https://example.org/a.png" srcset="https://evil.example/a 2x">',
        '<svg><a href="https://example.org">x</a></svg>',
        '<meta http-equiv="refresh" content="0;url=https://evil.example">',
        '<base href="https://evil.example/">',
    ],
)
def test_preflight_rejects_html_attribute_and_active_content_bypasses(content):
    manifest = _manifest(content=content)

    with pytest.raises(ManifestError):
        validate_manifest(manifest)


def test_preflight_allows_only_minimal_public_https_links_and_images():
    manifest = _manifest(
        content=(
            '<h2>摘要</h2><p><strong>事实：</strong>'
            '<a href="https://example.org/source">原文</a>'
            '<img src="https://example.org/cover.png" alt="封面" width="640">'
            "</p>"
        )
    )

    validate_manifest(manifest)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.org/brief",
        "javascript:alert(1)",
        "https://user:password" + "@example.org/brief",
        r"https://example.org\brief",
        "https://127.0.0.1/brief",
        "https://localhost/brief",
        "https://zhihu.com/question/1",
        "https://mp.weixin.qq.com/s/example",
        "https://baidu.com/example",
    ],
)
def test_content_source_url_must_be_empty_or_public_https(url):
    manifest = _manifest()
    manifest["article"]["content_source_url"] = url

    with pytest.raises(ManifestError):
        validate_manifest(manifest)


def test_content_source_url_may_be_empty():
    manifest = _manifest()
    manifest["article"]["content_source_url"] = ""

    validate_manifest(manifest)


@pytest.mark.parametrize(
    "url",
    [
        "file:///C:/private/source.html",
        r"C:\private\source.html",
        "https://user:password" + "@example.org/source",
        r"https://example.org\source",
        "https://zhihu.com/question/1",
        "https://sub.zhihu.com/article/1",
        "https://mp.weixin.qq.com/s/example",
        "https://developers.weixin.qq.com/doc/example",
        "https://baidu.com/example",
        "https://baike.baidu.com/item/example",
        "https://zhidao.baidu.com/question/example",
        "http://127.0.0.1/source",
        "http://localhost/source",
        "http://2130706433/source",
        "https://127.1/source",
        "https://0x7f000001/source",
    ],
)
def test_preflight_rejects_nonpublic_or_blacklisted_sources_before_network(tmp_path, url):
    manifest = _manifest()
    manifest["sources"] = [{"url": url}]
    service, session = _service(tmp_path, [])

    with pytest.raises(ManifestError):
        service.run(manifest)

    assert session.calls == []


def test_approved_delivery_can_resume_a_previously_staged_draft(tmp_path):
    manifest = _manifest(delivery="mass")
    staged, staged_session = _service(
        tmp_path,
        [
            {"access_token": "token-secret", "expires_in": 7200},
            {"media_id": "draft-id"},
        ],
    )
    assert staged.run(manifest)["state"] == "pending_approval"

    manifest["approval"] = build_approval(
        manifest,
        APPROVAL_PRIVATE_KEY,
        approved_at=_approved_at_now(),
    )
    resumed, resumed_session = _service(
        tmp_path,
        [
            {"access_token": "token-secret-2", "expires_in": 7200},
            {"errcode": 0, "msg_id": 321},
            {"msg_id": 321, "msg_status": "SEND_SUCCESS"},
        ],
        enabled=True,
        approval_public_key=APPROVAL_PUBLIC_KEY_PEM,
    )

    result = resumed.run(manifest)

    assert result["state"] == "delivered"
    assert result["delivery_verified"] is True
    assert len([c for c in staged_session.calls if c["url"].endswith("/draft/add")]) == 1
    assert not any(c["url"].endswith("/draft/add") for c in resumed_session.calls)


@pytest.mark.parametrize(
    "approved_at",
    [
        "not-a-date",
        "2026-08-14T21:00:00",
        (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(timespec="seconds"),
        (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat(timespec="seconds"),
    ],
)
def test_public_delivery_rejects_malformed_future_or_stale_approval(
    tmp_path, approved_at
):
    manifest = _manifest(delivery="publish")
    manifest["approval"] = _signed_approval_at(manifest, approved_at)
    service, session = _service(
        tmp_path,
        [],
        enabled=True,
        approval_public_key=APPROVAL_PUBLIC_KEY_PEM,
    )

    with pytest.raises(ApprovalError):
        service.run(manifest)

    assert session.calls == []


def test_hmac_secret_cannot_authorize_public_delivery(tmp_path):
    manifest = _manifest(delivery="publish")
    manifest["approval"] = {
        "algorithm": "HMAC-SHA256",
        "scope": "wechat-publication-v1:wechat_official:2026-08-14:daily:publish",
        **compute_manifest_hashes(manifest),
        "approved_at": _approved_at_now(),
        "signature": "0" * 64,
    }
    service, session = _service(
        tmp_path,
        [],
        enabled=True,
        approval_public_key="legacy-shared-secret",
    )

    with pytest.raises(ApprovalError):
        service.run(manifest)

    assert session.calls == []


def test_concurrent_draft_submission_has_one_remote_caller(tmp_path):
    class BlockingDraftClient:
        def __init__(self):
            self.entered = threading.Event()
            self.release = threading.Event()
            self.calls = 0
            self.lock = threading.Lock()

        def add_draft(self, article):
            with self.lock:
                self.calls += 1
            self.entered.set()
            assert self.release.wait(timeout=5)
            return {"media_id": "draft-id"}

    manifest = _manifest(delivery="draft")
    client = BlockingDraftClient()
    ledger_path = tmp_path / "wechat.sqlite3"
    first = PublicationService(client, PublicationLedger(ledger_path), poll_interval=0)
    second = PublicationService(client, PublicationLedger(ledger_path), poll_interval=0)

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(first.run, manifest)
        assert client.entered.wait(timeout=5)
        concurrent_result = second.run(manifest)
        client.release.set()
        first_result = first_future.result(timeout=5)

    assert concurrent_result["state"] == "in_progress"
    assert concurrent_result["operation"] == "draft"
    assert concurrent_result["delivery_verified"] is False
    assert first_result["state"] == "drafted"
    assert client.calls == 1
    assert second.run(manifest)["state"] == "drafted"
    assert client.calls == 1


_VALID_ONE_PIXEL_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


class ProbeResponse:
    def __init__(self, *, json_payload=None, chunks=(), status_code=200, content_type=None):
        self._json_payload = json_payload
        self._chunks = list(chunks)
        self.status_code = status_code
        self.headers = {"Content-Type": content_type} if content_type else {}
        self.closed = False
        self.iterated = False

    def json(self):
        if self._json_payload is None:
            raise ValueError("not JSON")
        return self._json_payload

    def iter_content(self, chunk_size):
        assert chunk_size > 0
        self.iterated = True
        yield from self._chunks

    @property
    def content(self):
        raise AssertionError("probe must stream instead of buffering response.content")

    def close(self):
        self.closed = True


class ProbeSession:
    def __init__(self, *, stable, draft=(), material=()):
        self.stable = list(stable)
        self.draft = list(draft)
        self.material = list(material)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append({"method": "POST", "url": url, **kwargs})
        if url.endswith("/cgi-bin/stable_token"):
            return self.stable.pop(0)
        if url.endswith("/cgi-bin/material/get_material"):
            return self.material.pop(0)
        raise AssertionError(f"write endpoint reached by probe: {url}")

    def get(self, url, **kwargs):
        self.calls.append({"method": "GET", "url": url, **kwargs})
        if url.endswith("/cgi-bin/draft/count"):
            return self.draft.pop(0)
        raise AssertionError(f"unexpected GET {url}")


def _probe_success_session(material_response=None):
    material_response = material_response or ProbeResponse(
        chunks=[_VALID_ONE_PIXEL_PNG], content_type="image/png"
    )
    return ProbeSession(
        stable=[ProbeResponse(json_payload={"access_token": "token-value", "expires_in": 7200})],
        draft=[ProbeResponse(json_payload={"total_count": 7})],
        material=[material_response],
    )


def test_readonly_probe_uses_get_shared_token_and_validates_binary_cover():
    material_response = ProbeResponse(
        chunks=[_VALID_ONE_PIXEL_PNG[:20], _VALID_ONE_PIXEL_PNG[20:]],
        content_type="image/png",
    )
    session = _probe_success_session(material_response)
    client = WeChatApiClient("wx-app-value", "secret-value", session=session)

    result = client.probe_account("media-value")

    assert result == {
        "status": "OK",
        "token_ok": True,
        "draft_count_ok": True,
        "total_count": 7,
        "cover_ok": True,
        "cover_kind": "png",
        "code": "OK",
        "category": "OK",
    }
    assert [call["method"] for call in session.calls] == ["POST", "GET", "POST"]
    assert all(call["allow_redirects"] is False for call in session.calls)
    assert session.calls[0]["url"].endswith("/cgi-bin/stable_token")
    assert session.calls[0]["json"]["force_refresh"] is False
    assert session.calls[1]["url"].endswith("/cgi-bin/draft/count")
    assert "json" not in session.calls[1]
    assert session.calls[2]["url"].endswith("/cgi-bin/material/get_material")
    assert session.calls[2]["json"] == {"media_id": "media-value"}
    assert session.calls[2]["stream"] is True
    assert session.calls[1]["params"] == session.calls[2]["params"] == {
        "access_token": "token-value"
    }
    assert material_response.iterated is True
    assert material_response.closed is True
    assert not any(
        forbidden in call["url"]
        for call in session.calls
        for forbidden in ("/draft/add", "/freepublish/", "/message/mass/")
    )


def test_readonly_probe_bounds_stream_and_closes_material_response():
    material_response = ProbeResponse(
        chunks=[b"1234567890", b"abcdefghij"], content_type="image/png"
    )
    session = _probe_success_session(material_response)
    client = WeChatApiClient("wx-app-value", "secret-value", session=session)

    result = client.probe_account("media-value", max_material_bytes=16)

    assert result["status"] == "FAILED"
    assert result["code"] == "MATERIAL_TOO_LARGE"
    assert result["category"] == "MATERIAL"
    assert result["cover_ok"] is False
    assert material_response.closed is True


def test_readonly_probe_json_errcode_is_sanitized():
    private_values = ("secret-value", "token-value", "media-value", "echoed-errmsg")
    body = json.dumps(
        {
            "errcode": 40007,
            "errmsg": "echoed-errmsg secret-value token-value media-value",
        }
    ).encode("utf-8")
    session = _probe_success_session(
        ProbeResponse(chunks=[body], content_type="application/json")
    )
    client = WeChatApiClient("wx-app-value", "secret-value", session=session)

    result = client.probe_account("media-value")

    assert result["code"] == "40007"
    assert result["category"] == "MATERIAL"
    serialized = json.dumps(result)
    assert "errmsg" not in serialized
    assert all(value not in serialized for value in private_values)


def test_readonly_probe_rejects_corrupt_png_structure():
    corrupt_png = bytearray(_VALID_ONE_PIXEL_PNG)
    corrupt_png[-8] ^= 0x01
    session = _probe_success_session(
        ProbeResponse(chunks=[bytes(corrupt_png)], content_type="image/png")
    )
    client = WeChatApiClient("wx-app-value", "secret-value", session=session)

    result = client.probe_account("media-value")

    assert result["code"] == "INVALID_IMAGE"
    assert result["category"] == "MATERIAL"
    assert result["cover_ok"] is False


@pytest.mark.parametrize(
    ("response", "expected_code"),
    [
        (ProbeResponse(json_payload={}, status_code=503), "HTTP_ERROR"),
        (ProbeResponse(json_payload=["unexpected"]), "UNEXPECTED_RESPONSE"),
    ],
)
def test_readonly_probe_classifies_http_and_unexpected_response_as_unknown(
    response, expected_code
):
    session = ProbeSession(stable=[response])
    client = WeChatApiClient("wx-app-value", "secret-value", session=session)

    result = client.probe_account("media-value")

    assert result["code"] == expected_code
    assert result["category"] == "UNKNOWN"
    assert result["token_ok"] is False


def test_readonly_probe_classifies_timeout_as_unknown():
    class TimeoutSession:
        def post(self, url, **kwargs):
            raise TimeoutError("secret-value token-value media-value")

    client = WeChatApiClient("wx-app-value", "secret-value", session=TimeoutSession())

    result = client.probe_account("media-value")

    assert result["code"] == "REQUEST_ERROR"
    assert result["category"] == "UNKNOWN"
    assert "secret-value" not in json.dumps(result)


@pytest.mark.parametrize(
    ("errcode", "category"),
    [
        (40002, "CONFIG"),
        (40013, "CONFIG"),
        (41002, "CONFIG"),
        (41004, "CONFIG"),
        (43002, "CONFIG"),
        (40125, "CONFIG"),
        (40164, "IP_ALLOWLIST"),
        (45035, "IP_ALLOWLIST"),
        (61004, "IP_ALLOWLIST"),
        (48001, "PERMISSION"),
        (48004, "PERMISSION"),
        (89503, "PERMISSION"),
        (89506, "PERMISSION"),
        (89507, "PERMISSION"),
        (40001, "TOKEN"),
        (40014, "TOKEN"),
        (42001, "TOKEN"),
        (40007, "MATERIAL"),
        (-1, "TRANSIENT"),
        (45009, "QUOTA"),
        (45011, "QUOTA"),
    ],
)
def test_readonly_probe_classifies_known_errcodes_without_errmsg(errcode, category):
    session = ProbeSession(
        stable=[
            ProbeResponse(
                json_payload={
                    "errcode": errcode,
                    "errmsg": "must-not-appear secret-value",
                }
            )
        ]
    )
    client = WeChatApiClient("wx-app-value", "secret-value", session=session)

    result = client.probe_account("media-value")

    assert result["code"] == str(errcode)
    assert result["category"] == category
    assert "must-not-appear" not in json.dumps(result)


def test_readonly_probe_refetches_token_at_most_once_without_force_refresh():
    session = ProbeSession(
        stable=[
            ProbeResponse(json_payload={"access_token": "token-one", "expires_in": 7200}),
            ProbeResponse(json_payload={"access_token": "token-two", "expires_in": 7200}),
        ],
        draft=[
            ProbeResponse(json_payload={"errcode": 42001, "errmsg": "expired token-one"}),
            ProbeResponse(json_payload={"errcode": 42001, "errmsg": "expired token-two"}),
        ],
    )
    client = WeChatApiClient("wx-app-value", "secret-value", session=session)

    result = client.probe_account("media-value")

    assert result["code"] == "42001"
    assert result["category"] == "TOKEN"
    stable_calls = [call for call in session.calls if call["url"].endswith("/stable_token")]
    draft_calls = [call for call in session.calls if call["url"].endswith("/draft/count")]
    assert len(stable_calls) == 2
    assert len(draft_calls) == 2
    assert all(call["json"]["force_refresh"] is False for call in stable_calls)
    assert not any(call["url"].endswith("/get_material") for call in session.calls)


def test_probe_cli_uses_secure_vault_only_and_emits_allowlisted_json(
    tmp_path, monkeypatch, capsys
):
    from scripts import probe_wechat_mp as probe

    events = []
    paths = SimpleNamespace(
        runtime_dir=tmp_path / "runtime",
        vault_path=tmp_path / "runtime" / ".wechat_mp.vault",
    )
    monkeypatch.setattr(probe, "resolve_runtime_paths", lambda environment: paths)
    monkeypatch.setattr(
        probe, "ensure_secure_directory", lambda path: events.append(("secure", path))
    )

    class Vault:
        def __init__(self, path):
            events.append(("vault", path))

        def load(self):
            events.append(("load", None))
            return {
                "app_id": "wx-app-value",
                "app_secret": "secret-value",
                "thumb_media_id": "media-value",
            }

    class ReadOnlyClient:
        def __init__(self, app_id, app_secret):
            assert (app_id, app_secret) == ("wx-app-value", "secret-value")
            events.append(("client", None))

        def add_draft(self, article):
            raise AssertionError("probe must never add a draft")

        def probe_account(self, media_id):
            assert media_id == "media-value"
            events.append(("probe", None))
            return {
                "status": "OK",
                "token_ok": True,
                "draft_count_ok": True,
                "total_count": 3,
                "cover_ok": True,
                "cover_kind": "png",
                "code": "OK",
                "category": "OK",
                "access_token": "token-value",
                "media_id": "media-value",
                "errmsg": "secret-value",
            }

    monkeypatch.setattr(probe, "WechatCredentialVault", Vault)
    monkeypatch.setattr(probe, "WeChatApiClient", ReadOnlyClient)

    assert probe.main([], environment={"WECHAT_RUNTIME_DIR": str(paths.runtime_dir)}) == 0

    stdout = capsys.readouterr().out.strip()
    result = json.loads(stdout)
    assert set(result) == {
        "status",
        "token_ok",
        "draft_count_ok",
        "total_count",
        "cover_ok",
        "cover_kind",
        "code",
        "category",
    }
    assert all(value not in stdout for value in ("wx-app-value", "secret-value", "token-value", "media-value", "errmsg"))
    assert [event[0] for event in events] == ["secure", "vault", "load", "client", "probe"]
    assert not hasattr(probe, "PublicationLedger")


def test_probe_cli_missing_vault_configuration_fails_closed_before_client(
    tmp_path, monkeypatch, capsys
):
    from scripts import probe_wechat_mp as probe

    paths = SimpleNamespace(
        runtime_dir=tmp_path / "runtime",
        vault_path=tmp_path / "runtime" / ".wechat_mp.vault",
    )
    monkeypatch.setattr(probe, "resolve_runtime_paths", lambda environment: paths)
    monkeypatch.setattr(probe, "ensure_secure_directory", lambda path: None)

    class IncompleteVault:
        def __init__(self, path):
            self.path = path

        def load(self):
            return {"app_id": "wx-app-value", "app_secret": "secret-value"}

    class NeverClient:
        def __init__(self, *args, **kwargs):
            raise AssertionError("client must not be built with incomplete configuration")

    monkeypatch.setattr(probe, "WechatCredentialVault", IncompleteVault)
    monkeypatch.setattr(probe, "WeChatApiClient", NeverClient)

    assert probe.main([], environment={"WECHAT_RUNTIME_DIR": str(paths.runtime_dir)}) == 2

    stdout = capsys.readouterr().out.strip()
    result = json.loads(stdout)
    assert result["status"] == "BLOCKED"
    assert result["code"] == "CONFIG_MISSING"
    assert result["category"] == "CONFIG"
    assert "secret-value" not in stdout


def test_probe_cli_runtime_security_blocks_before_vault_access(tmp_path, monkeypatch, capsys):
    from scripts import probe_wechat_mp as probe
    from wechat_runtime import RuntimeSecurityError

    paths = SimpleNamespace(
        runtime_dir=tmp_path / "unsafe-runtime",
        vault_path=tmp_path / "unsafe-runtime" / ".wechat_mp.vault",
    )
    monkeypatch.setattr(probe, "resolve_runtime_paths", lambda environment: paths)

    def reject_runtime(path):
        raise RuntimeSecurityError("private path must not be printed")

    class NeverVault:
        def __init__(self, path):
            raise AssertionError("vault must not be opened before runtime security passes")

    monkeypatch.setattr(probe, "ensure_secure_directory", reject_runtime)
    monkeypatch.setattr(probe, "WechatCredentialVault", NeverVault)

    assert probe.main([], environment={"WECHAT_RUNTIME_DIR": str(paths.runtime_dir)}) == 2

    stdout = capsys.readouterr().out.strip()
    result = json.loads(stdout)
    assert result["code"] == "RUNTIME_SECURITY_ERROR"
    assert "private path" not in stdout


def test_prepare_preserves_runtime_security_error_from_vault_at_main_boundary(
    tmp_path, monkeypatch, capsys
):
    from scripts import run_daily_wechat as cli
    from wechat_runtime import RuntimeSecurityError

    issue_path = tmp_path / "issue.json"
    _write_issue(issue_path, include_cover=False)

    class SecurityFailVault:
        def __init__(self, path):
            self.path = path

        def load(self):
            raise RuntimeSecurityError("sensitive path detail")

    monkeypatch.setattr(cli, "WechatCredentialVault", SecurityFailVault)

    result = cli.main(
        ["--content", str(issue_path), "--action", "prepare"],
        environment={"WECHAT_RUNTIME_DIR": str(tmp_path / "runtime")},
    )

    assert result == 2
    assert json.loads(capsys.readouterr().out) == {
        "status": "BLOCKED",
        "code": "RUNTIME_SECURITY_ERROR",
        "delivery_verified": False,
    }
