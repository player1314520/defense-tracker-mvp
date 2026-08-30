from pathlib import Path

import pytest

import app as tracker


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _request_ip(remote_addr: str, forwarded_for: str | None = None) -> str:
    headers = {}
    if forwarded_for is not None:
        headers["X-Forwarded-For"] = forwarded_for
    with tracker.app.test_request_context(
        "/api/status",
        headers=headers,
        environ_overrides={"REMOTE_ADDR": remote_addr},
    ):
        return tracker._get_ip()


def test_direct_local_request_remains_usable_without_trusted_proxy_config(
    monkeypatch,
):
    monkeypatch.delenv("DEFENSE_TRACKER_TRUSTED_PROXIES", raising=False)

    assert _request_ip("127.0.0.1", "203.0.113.7") == "127.0.0.1"


def test_untrusted_peer_cannot_spoof_rate_identity_with_forwarded_for(monkeypatch):
    monkeypatch.setenv("DEFENSE_TRACKER_TRUSTED_PROXIES", "10.0.0.0/8")

    assert (
        _request_ip("198.51.100.20", "203.0.113.7, 10.1.2.3")
        == "198.51.100.20"
    )


def test_untrusted_peer_cannot_rotate_forwarded_for_to_bypass_login_limit(
    monkeypatch,
):
    monkeypatch.setattr(tracker, "AUTH_REQUIRED", True)
    monkeypatch.setenv("DEFENSE_TRACKER_TRUSTED_PROXIES", "10.0.0.0/8")
    client = tracker.app.test_client()

    responses = [
        client.post(
            "/login",
            data={"token": "invalid"},
            headers={"X-Forwarded-For": f"203.0.113.{index}"},
            environ_overrides={"REMOTE_ADDR": "198.51.100.20"},
        )
        for index in range(1, 7)
    ]

    assert [response.status_code for response in responses[:5]] == [200] * 5
    assert responses[5].status_code == 429


def test_trusted_single_hop_proxy_supplies_canonical_ipv4_identity(monkeypatch):
    monkeypatch.setenv("DEFENSE_TRACKER_TRUSTED_PROXIES", "10.1.2.3")

    assert _request_ip("10.1.2.3", "203.0.113.7") == "203.0.113.7"


def test_trusted_proxy_keeps_legitimate_clients_in_separate_login_buckets(
    monkeypatch,
):
    monkeypatch.setattr(tracker, "AUTH_REQUIRED", True)
    monkeypatch.setenv("DEFENSE_TRACKER_TRUSTED_PROXIES", "10.1.2.3")
    client = tracker.app.test_client()

    first_client = [
        client.post(
            "/login",
            data={"token": "invalid"},
            headers={"X-Forwarded-For": "203.0.113.7"},
            environ_overrides={"REMOTE_ADDR": "10.1.2.3"},
        )
        for _ in range(5)
    ]
    second_client = client.post(
        "/login",
        data={"token": "invalid"},
        headers={"X-Forwarded-For": "203.0.113.8"},
        environ_overrides={"REMOTE_ADDR": "10.1.2.3"},
    )
    first_client_limited = client.post(
        "/login",
        data={"token": "invalid"},
        headers={"X-Forwarded-For": "203.0.113.7"},
        environ_overrides={"REMOTE_ADDR": "10.1.2.3"},
    )

    assert [response.status_code for response in first_client] == [200] * 5
    assert second_client.status_code == 200
    assert first_client_limited.status_code == 429


def test_trusted_proxy_walk_stops_at_rightmost_untrusted_hop(monkeypatch):
    monkeypatch.setenv(
        "DEFENSE_TRACKER_TRUSTED_PROXIES",
        "10.0.0.0/8, 192.0.2.0/24",
    )

    assert (
        _request_ip(
            "10.1.2.3",
            "1.2.3.4, 198.51.100.40, 192.0.2.25",
        )
        == "198.51.100.40"
    )


def test_trusted_proxy_allowlist_accepts_mixed_linear_delimiters(monkeypatch):
    monkeypatch.setenv(
        "DEFENSE_TRACKER_TRUSTED_PROXIES",
        "10.0.0.0/8  192.0.2.0/24,\t2001:db8:ffff::/48",
    )

    assert _request_ip("10.1.2.3", "203.0.113.7") == "203.0.113.7"


def test_trusted_ipv6_proxy_supplies_canonical_ipv6_identity(monkeypatch):
    monkeypatch.setenv(
        "DEFENSE_TRACKER_TRUSTED_PROXIES",
        "2001:db8:ffff::/48",
    )

    assert (
        _request_ip("2001:db8:ffff::10", "2001:0db8:0001:0000::0007")
        == "2001:db8:1::7"
    )


@pytest.mark.parametrize(
    "invalid_config",
    (
        "10.0.0.1/8",
        "10.0.0.0/8,not-a-network",
        "2001:db8::1/32",
        "10.0.0.0/8,,192.0.2.0/24",
        "10.0.0.0/8,  ,192.0.2.0/24",
    ),
)
def test_invalid_trusted_proxy_config_fails_closed(monkeypatch, invalid_config):
    monkeypatch.setenv("DEFENSE_TRACKER_TRUSTED_PROXIES", invalid_config)

    assert _request_ip("10.1.2.3", "203.0.113.7") == "10.1.2.3"


@pytest.mark.parametrize(
    "invalid_forwarded_for",
    (
        "203.0.113.7, not-an-ip",
        "203.0.113.7,,192.0.2.1",
        "fe80::1%attacker-controlled-zone",
    ),
)
def test_invalid_forwarded_for_fails_closed_to_peer(
    monkeypatch,
    invalid_forwarded_for,
):
    monkeypatch.setenv("DEFENSE_TRACKER_TRUSTED_PROXIES", "10.0.0.0/8")

    assert _request_ip("10.1.2.3", invalid_forwarded_for) == "10.1.2.3"


def test_oversized_or_excessive_forwarded_chain_fails_closed(monkeypatch):
    monkeypatch.setenv("DEFENSE_TRACKER_TRUSTED_PROXIES", "10.0.0.0/8")
    oversized = "203.0.113.7," + (" " * 1100)
    excessive = ",".join(f"192.0.2.{index}" for index in range(1, 19))

    assert _request_ip("10.1.2.3", oversized) == "10.1.2.3"
    assert _request_ip("10.1.2.3", excessive) == "10.1.2.3"


def test_malformed_peer_never_becomes_an_unbounded_rate_key(monkeypatch):
    monkeypatch.setenv("DEFENSE_TRACKER_TRUSTED_PROXIES", "0.0.0.0/0")

    rate_identity = _request_ip("x" * 10000, "y" * 10000)

    assert rate_identity == "unknown"
    assert len(rate_identity) <= 45


def test_nginx_overwrites_client_forwarding_headers_for_every_proxy_location():
    nginx = (PROJECT_ROOT / "deploy" / "nginx.conf").read_text(encoding="utf-8")

    assert "$proxy_add_x_forwarded_for" not in nginx
    assert nginx.count("X-Forwarded-For   $remote_addr;") == 4


def test_compose_pins_only_the_nginx_proxy_address_as_trusted():
    compose = (PROJECT_ROOT / "deploy" / "docker-compose.yml").read_text(
        encoding="utf-8",
    )

    exact_ip = "${DEFENSE_TRACKER_NGINX_PROXY_IP:-172.30.240.2}"
    assert f'DEFENSE_TRACKER_TRUSTED_PROXIES: "{exact_ip}"' in compose
    assert f'ipv4_address: "{exact_ip}"' in compose
    assert '${DEFENSE_TRACKER_DOCKER_SUBNET:-172.30.240.0/29}' in compose
    assert 'DEFENSE_TRACKER_TRUSTED_PROXIES: "172.30.240.0/29"' not in compose
    tracker_section = compose.split("  tracker:", 1)[1].split("  nginx:", 1)[0]
    assert "ports:" not in tracker_section
    assert 'expose:\n      - "5000"' in tracker_section
