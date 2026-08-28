#!/usr/bin/env python3
"""Redaction-safe public smoke probe for the production MVP endpoints."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import urllib.error
import urllib.request


class ProbeFailure(RuntimeError):
    pass


def _default_version_paths() -> tuple[Path, ...]:
    configured = (os.environ.get("DEFENSE_TRACKER_VERSION_FILE") or "").strip()
    if configured:
        configured_path = Path(configured).expanduser()
        if not configured_path.is_absolute():
            raise ProbeFailure("configured version metadata path is not absolute")
        return (configured_path,)
    # Source/deployment checkout: deploy/mvp/bin/probe-public.py -> repo root.
    # Portal container: product_version.py and version.json live under /app.
    source_root = Path(__file__).resolve().parents[3]
    return (source_root / "version.json", Path("/app/version.json"))


def load_product_version_metadata(path: Path | None = None) -> dict[str, object]:
    candidates = (path,) if path is not None else _default_version_paths()
    version_path = next((candidate for candidate in candidates if candidate.is_file()), None)
    if version_path is None:
        raise ProbeFailure("product version metadata is unavailable")
    try:
        payload = json.loads(version_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProbeFailure("product version metadata is invalid") from exc
    if not isinstance(payload, dict) or payload.get("schema") != 1:
        raise ProbeFailure("product version metadata has an unsupported schema")
    required = ("semantic_version", "display_version", "release_tag")
    if any(not isinstance(payload.get(key), str) or not payload[key] for key in required):
        raise ProbeFailure("product version metadata is incomplete")
    semantic_version = str(payload["semantic_version"])
    version_parts = semantic_version.split(".")
    if len(version_parts) != 3 or any(not part.isdigit() for part in version_parts):
        raise ProbeFailure("product semantic version is invalid")
    if payload["release_tag"] != f"v{semantic_version}":
        raise ProbeFailure("product release tag differs from semantic version")
    if payload["display_version"] != f"V{int(version_parts[0])}":
        raise ProbeFailure("product display version differs from semantic version")
    return payload


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    return values


def request_bytes(
    url: str,
    *,
    key: str = "",
    origin: str = "",
    body: bytes | None = None,
    expected_statuses: tuple[int, ...] = (200, 202),
) -> bytes:
    headers = {
        "Accept": "application/json",
        "User-Agent": "DefenseTracker-MVP-Probe/1",
    }
    if key:
        headers["apikey"] = key
        headers["Authorization"] = f"Bearer {key}"
    if origin:
        headers["Origin"] = origin
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        url,
        headers=headers,
        data=body,
        method="POST" if body is not None else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            status = int(response.status)
            payload = response.read(1024 * 1024 + 1)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        payload = exc.read(1024 * 1024 + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ProbeFailure("public endpoint request failed") from exc
    if status not in expected_statuses:
        raise ProbeFailure("unexpected HTTP status")
    if len(payload) > 1024 * 1024:
        raise ProbeFailure("public endpoint response exceeded the probe limit")
    return payload


def request_json(url: str, **kwargs: object) -> dict[str, object]:
    payload = request_bytes(url, **kwargs)
    try:
        parsed = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProbeFailure("public endpoint returned invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise ProbeFailure("public endpoint returned a non-object JSON value")
    return parsed


def verify_release_metadata(
    payload: dict[str, object],
    commit: str,
    product_version: dict[str, object],
) -> None:
    expected = {
        "version": product_version["semantic_version"],
        "display_version": product_version["display_version"],
        "release_tag": product_version["release_tag"],
        "build_commit": commit,
        "wire_compatibility": "mvp-wire-v1",
    }
    if any(payload.get(key) != value for key, value in expected.items()):
        raise ProbeFailure("public release metadata differs from the deployment")


def probe_realtime_websocket(api_domain: str, key: str) -> None:
    websocket_key = base64.b64encode(os.urandom(16)).decode("ascii")
    expected_accept = base64.b64encode(
        hashlib.sha1(
            (websocket_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii"),
            usedforsecurity=False,
        ).digest()
    ).decode("ascii")
    request_lines = [
        "GET /realtime/v1/websocket?vsn=1.0.0 HTTP/1.1",
        f"Host: {api_domain}",
        "Connection: Upgrade",
        "Upgrade: websocket",
        "Sec-WebSocket-Version: 13",
        f"Sec-WebSocket-Key: {websocket_key}",
        f"apikey: {key}",
        f"Authorization: Bearer {key}",
        "User-Agent: DefenseTracker-MVP-Probe/1",
        "",
        "",
    ]
    context = ssl.create_default_context()
    context.set_alpn_protocols(["http/1.1"])
    try:
        with socket.create_connection((api_domain, 443), timeout=15) as raw:
            with context.wrap_socket(raw, server_hostname=api_domain) as tls:
                tls.sendall("\r\n".join(request_lines).encode("ascii"))
                response = b""
                while b"\r\n\r\n" not in response and len(response) <= 32768:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    response += chunk
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        raise ProbeFailure("Realtime WebSocket TLS handshake failed") from exc
    header_block = response.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1")
    lines = header_block.split("\r\n")
    if not lines or " 101 " not in f" {lines[0]} ":
        raise ProbeFailure("Realtime WebSocket did not return HTTP 101")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    if headers.get("sec-websocket-accept") != expected_accept:
        raise ProbeFailure("Realtime WebSocket accept value is invalid")


def main() -> int:
    if len(sys.argv) > 2:
        raise SystemExit("usage: probe-public.py [PRODUCTION_ENV]")
    production_path = Path(sys.argv[1] if len(sys.argv) == 2 else "/etc/defense-tracker/production.env")
    product_version = load_product_version_metadata()
    production = load_env(production_path)
    stack_dir = Path(production["SUPABASE_STACK_DIR"])
    upstream = load_env(stack_dir / ".env")
    key_file = Path(production["MVP_SECRETS_DIR"]) / "supabase_publishable_key"
    portal_key = key_file.read_text(encoding="ascii").strip()
    official_key = upstream.get("SUPABASE_PUBLISHABLE_KEY", "")
    if not portal_key.startswith("sb_publishable_") or not hmac.compare_digest(portal_key, official_key):
        raise ProbeFailure("Portal and official Supabase publishable keys differ")

    portal_domain = production["PORTAL_DOMAIN"]
    api_domain = production["API_DOMAIN"]
    portal_origin = f"https://{portal_domain}"
    api_origin = f"https://{api_domain}"
    release_commit = production["MVP_EXPECTED_RELEASE_SHA"]
    if len(release_commit) != 40 or any(
        character not in "0123456789abcdef" for character in release_commit
    ):
        raise ProbeFailure("expected release commit is invalid")

    ready = request_json(f"{portal_origin}/ready")
    if ready.get("status") != "ready":
        raise ProbeFailure("Portal dependency readiness failed")
    verify_release_metadata(ready, release_commit, product_version)
    status_payload = request_json(f"{portal_origin}/api/status")
    verify_release_metadata(status_payload, release_commit, product_version)
    config = request_json(f"{portal_origin}/portal/config.json")
    if (
        config.get("configured") is not True
        or config.get("url") != api_origin
        or not isinstance(config.get("publishable_key"), str)
        or not hmac.compare_digest(str(config["publishable_key"]), official_key)
    ):
        raise ProbeFailure("Portal public configuration differs from the official stack")
    verify_release_metadata(config, release_commit, product_version)

    request_json(f"{api_origin}/auth/v1/health", key=portal_key)
    request_json(f"{api_origin}/storage/v1/status", key=portal_key)
    apply = request_json(
        f"{api_origin}/functions/v1/access-applications",
        key=portal_key,
        origin=portal_origin,
        body=json.dumps(
            {
                "action": "apply",
                "email": "not-an-email",
                "terms_version": "mvp-probe-v1",
            },
            separators=(",", ":"),
        ).encode("utf-8"),
        expected_statuses=(202,) if config.get("access_applications_enabled") is True else (503,),
    )
    if config.get("access_applications_enabled") is True:
        if apply.get("status") != "received":
            raise ProbeFailure("anonymous access application route did not accept the probe")
    elif config.get("access_applications_enabled") is False:
        if apply.get("error") != "applications_closed":
            raise ProbeFailure("closed application route did not fail closed")
    else:
        raise ProbeFailure("Portal application gate has an invalid value")
    probe_realtime_websocket(api_domain, portal_key)

    print("[PROBE] Portal readiness/config, Auth, Storage health, application gate and Realtime WebSocket passed.")
    print("[PROBE] RPC presence was verified in Postgres; authentication-required business flows are not part of this probe.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, OSError, ProbeFailure) as exc:
        print(f"[PROBE] failed: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(70)
