#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fail-closed external probe for WAF origin isolation.

Origin targets and the HMAC key are read only from protected environment
variables.  The output contains no hostname, address, URL, exception text, or
response body; it records only fixed gate names, pass/fail status, a keyed
target digest, and UTC timestamps.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


DNS_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
TARGET_ENVIRONMENTS = {
    "staging": "DEFENSE_TRACKER_STAGING_ORIGIN_TARGET",
    "production": "DEFENSE_TRACKER_PRODUCTION_ORIGIN_TARGET",
}
HMAC_KEY_ENV = "DEFENSE_TRACKER_ORIGIN_EVIDENCE_HMAC_KEY"
CONNECT_TIMEOUT_SECONDS = 5.0
MAX_ADDRESSES = 8


class ProbeFailure(RuntimeError):
    """A redaction-safe origin-isolation failure."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _origin_hostname(origin: str) -> str:
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except ValueError as exc:
        raise ProbeFailure("public origin is malformed") from exc
    if (
        origin != origin.lower()
        or parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or port not in (None, 443)
        or parsed.hostname is None
        or DNS_RE.fullmatch(parsed.hostname) is None
    ):
        raise ProbeFailure("public origin is malformed")
    return parsed.hostname


def _validate_target(target: str) -> str:
    if not target or target != target.strip() or not target.isascii():
        raise ProbeFailure("protected origin target is malformed")
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        if target != target.lower() or DNS_RE.fullmatch(target) is None:
            raise ProbeFailure("protected origin target is malformed")
    else:
        if not address.is_global:
            raise ProbeFailure("protected origin target is not public")
    return target


def _resolve_public(target: str, port: int, label: str) -> list[tuple[int, tuple[object, ...]]]:
    try:
        records = socket.getaddrinfo(target, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ProbeFailure(f"{label} target resolution failed") from exc
    resolved: list[tuple[int, tuple[object, ...]]] = []
    seen: set[tuple[int, str]] = set()
    for family, socket_type, protocol, _, sockaddr in records:
        if socket_type != socket.SOCK_STREAM or family not in (socket.AF_INET, socket.AF_INET6):
            continue
        address = str(sockaddr[0])
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ProbeFailure(f"{label} target resolution was invalid") from exc
        if not parsed.is_global:
            raise ProbeFailure(f"{label} target resolved outside public address space")
        key = (family, address)
        if key not in seen:
            resolved.append((family, sockaddr))
            seen.add(key)
    if not resolved or len(resolved) > MAX_ADDRESSES:
        raise ProbeFailure(f"{label} target resolution was empty or excessive")
    return resolved


def _resolved_addresses(target: str, port: int, label: str) -> set[str]:
    return {str(sockaddr[0]) for _, sockaddr in _resolve_public(target, port, label)}


def _tcp_is_blocked(addresses: list[tuple[int, tuple[object, ...]]]) -> bool:
    for family, sockaddr in addresses:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT_SECONDS)
        try:
            sock.connect(sockaddr)
        except OSError:
            continue
        finally:
            sock.close()
        return False
    return True


def _sni_tls_is_blocked(
    addresses: list[tuple[int, tuple[object, ...]]], server_name: str
) -> bool:
    context = ssl.create_default_context()
    for family, sockaddr in addresses:
        raw = socket.socket(family, socket.SOCK_STREAM)
        raw.settimeout(CONNECT_TIMEOUT_SECONDS)
        try:
            raw.connect(sockaddr)
        except OSError:
            raw.close()
            continue
        try:
            # Any TCP-reachable TLS listener is a source-bypass failure.  A
            # certificate or handshake error still proves the origin accepted
            # a direct connection, so it must not be treated as a blocked gate.
            with context.wrap_socket(raw, server_hostname=server_name):
                pass
        except (OSError, ssl.SSLError):
            raw.close()
        return False
    return True


def _public_health_reachable(server_name: str) -> bool:
    connection = http.client.HTTPSConnection(
        server_name,
        443,
        timeout=CONNECT_TIMEOUT_SECONDS,
        context=ssl.create_default_context(),
    )
    try:
        connection.request(
            "GET",
            "/health",
            headers={"Accept": "application/json", "User-Agent": "DefenseTracker-origin-gate/1"},
        )
        response = connection.getresponse()
        response.read(4096)
        return response.status == 200
    except (OSError, http.client.HTTPException, ssl.SSLError):
        return False
    finally:
        connection.close()


def _target_hmac(target: str, key: bytes) -> str:
    return hmac.new(key, target.lower().encode("utf-8"), hashlib.sha256).hexdigest()


def collect(
    staging_origin: str, production_origin: str
) -> tuple[dict[str, object], list[str]]:
    origins = {
        "staging": _origin_hostname(staging_origin),
        "production": _origin_hostname(production_origin),
    }
    raw_key = os.environ.get(HMAC_KEY_ENV, "")
    if len(raw_key.encode("utf-8")) < 32:
        raise ProbeFailure("protected evidence HMAC key is missing or too short")
    key = raw_key.encode("utf-8")

    gates: list[dict[str, str]] = []
    failures: list[str] = []
    for environment, target_env in TARGET_ENVIRONMENTS.items():
        target = _validate_target(os.environ.get(target_env, ""))
        hostname = origins[environment]
        target_80 = _resolve_public(target, 80, environment)
        target_443 = _resolve_public(target, 443, environment)
        public_addresses = _resolved_addresses(hostname, 443, f"{environment} public origin")
        target_addresses = {str(sockaddr[0]) for _, sockaddr in target_443}
        if public_addresses & target_addresses:
            raise ProbeFailure(f"{environment} target resolves to the public WAF endpoint")

        outcomes = {
            f"{environment}_public_edge_https_reachable": _public_health_reachable(
                hostname
            ),
            f"{environment}_origin_tcp_80_blocked": _tcp_is_blocked(target_80),
            f"{environment}_origin_tcp_443_blocked": _tcp_is_blocked(target_443),
            f"{environment}_origin_sni_443_blocked": _sni_tls_is_blocked(
                target_443, hostname
            ),
        }
        target_digest = _target_hmac(target, key)
        for gate, passed in outcomes.items():
            gates.append(
                {
                    "gate": gate,
                    "status": "pass" if passed else "fail",
                    "target_hmac_sha256": target_digest,
                    "observed_at_utc": _utc_now(),
                }
            )
            if not passed:
                failures.append(gate)
    return {"schema": 1, "gates": gates}, failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--staging-origin", required=True)
    parser.add_argument("--production-origin", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    try:
        evidence, failures = collect(args.staging_origin, args.production_origin)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(evidence, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            + "\n",
            encoding="utf-8",
        )
    except ProbeFailure as exc:
        print(f"origin-isolation: FAIL ({exc})", file=sys.stderr)
        return 1
    if failures:
        print("origin-isolation: FAIL (one or more direct-origin gates were reachable)", file=sys.stderr)
        return 1
    print("origin-isolation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
