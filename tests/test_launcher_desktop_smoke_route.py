# -*- coding: utf-8 -*-
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def test_desktop_smoke_route_requires_session_origin_csrf_and_edge(tmp_path):
    env = os.environ.copy()
    env.update(
        {
            "DEFENSE_TRACKER_HOME": str(tmp_path / "runtime"),
            "DEFENSE_TRACKER_SMOKE_EVIDENCE": "authenticated-loopback-v1",
            "DEFENSE_TRACKER_SMOKE_TOKEN": "b" * 64,
            "DEFENSE_TRACKER_BUILD_COMMIT": "a" * 40,
        }
    )
    # Importing launcher in a child process keeps its deliberate environment
    # and working-directory setup isolated from the rest of the test suite.
    probe = r"""
import json
import launcher
import app

base_url = f"http://127.0.0.1:{launcher.PORT}"
endpoint = launcher.DESKTOP_SMOKE_ENDPOINT
client = launcher.flask_app.test_client()
session = app._issue_auth_session()
assert session
client.set_cookie(app.AUTH_COOKIE, session, domain="127.0.0.1")
client.set_cookie(app.CSRF_COOKIE, "csrf-test", domain="127.0.0.1")
payload = {
    "schema": 1,
    "http_status": 200,
    "pathname": "/",
    "workspace_ready": True,
    "version": "9.0.0",
    "display_version": "V9",
    "release_tag": "v9.0.0",
    "build_commit": "a" * 40,
}
bearer = {"X-Defense-Tracker-Smoke": "b" * 64}
origin = {"Origin": base_url, "X-CSRF-Token": "csrf-test"}

statuses = {
    "unknown_bearer": client.get(
        endpoint,
        base_url=base_url,
        headers={"X-Defense-Tracker-Smoke": "not-a-token"},
    ).status_code,
    "not_ready": client.get(endpoint, base_url=base_url, headers=bearer).status_code,
    "missing_origin": client.post(
        endpoint,
        base_url=base_url,
        headers={"X-CSRF-Token": "csrf-test"},
        json=payload,
    ).status_code,
    "missing_csrf": client.post(
        endpoint,
        base_url=base_url,
        headers={"Origin": base_url},
        json=payload,
    ).status_code,
}
launcher._desktop_smoke_store.set_renderer("mshtml")
statuses["legacy_renderer"] = client.post(
    endpoint, base_url=base_url, headers=origin, json=payload
).status_code

# Use a fresh exact-renderer store after proving the fallback is rejected.
launcher._desktop_smoke_store = launcher.DesktopSmokeEvidenceStore(
    "9.0.0", "V9", "v9.0.0", "a" * 40
)
launcher._desktop_smoke_store.set_renderer("edgechromium")
statuses["extra_field"] = client.post(
    endpoint,
    base_url=base_url,
    headers=origin,
    json={**payload, "extra": "rejected"},
).status_code
statuses["accepted"] = client.post(
    endpoint, base_url=base_url, headers=origin, json=payload
).status_code
result = client.get(endpoint, base_url=base_url, headers=bearer)
statuses["retrieved"] = result.status_code
body = result.get_json()
assert body["process_id"] > 0
assert body["renderer"] == "edgechromium"
assert body["evidence"] == payload
print(json.dumps(statuses, sort_keys=True))
"""
    result = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    statuses = json.loads(result.stdout.splitlines()[-1])
    assert statuses == {
        "accepted": 204,
        "extra_field": 400,
        "legacy_renderer": 400,
        "missing_csrf": 403,
        "missing_origin": 404,
        "not_ready": 425,
        "retrieved": 200,
        "unknown_bearer": 404,
    }


def test_desktop_renderer_callback_allows_only_edgechromium(tmp_path):
    env = os.environ.copy()
    env["DEFENSE_TRACKER_HOME"] = str(tmp_path / "runtime")
    probe = r"""
import launcher
from webview.event import Event

launcher._wait_for_flask = lambda: True
launcher.get_desktop_bootstrap_token = lambda: "b" * 64
assert launcher._prepare_desktop_login_url() == (
    f"http://127.0.0.1:{launcher.PORT}/login#desktop=" + "b" * 64
)

launcher._desktop_smoke_store = launcher.DesktopSmokeEvidenceStore(
    "9.0.0", "V9", "v9.0.0", "a" * 40
)
allowed = Event(None, should_lock=True)
allowed += launcher._accept_desktop_renderer
assert allowed.set("WebView2") is False
assert launcher._desktop_renderer == "edgechromium"
assert launcher._desktop_smoke_store.renderer == "edgechromium"

launcher._desktop_smoke_store = launcher.DesktopSmokeEvidenceStore(
    "9.0.0", "V9", "v9.0.0", "a" * 40
)
rejected = Event(None, should_lock=True)
rejected += launcher._accept_desktop_renderer
assert rejected.set("mshtml") is True
assert launcher._desktop_renderer == "mshtml"
assert launcher._desktop_smoke_store.renderer is None

launcher._desktop_smoke_store = launcher.DesktopSmokeEvidenceStore(
    "9.0.0", "V9", "v9.0.0", "a" * 40
)
launcher._desktop_smoke_store.set_renderer("edgechromium")
assert launcher._accept_desktop_renderer("cef") is False
"""
    result = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
