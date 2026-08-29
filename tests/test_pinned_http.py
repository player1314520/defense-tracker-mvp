import gzip
import io
import json
import socket
import ssl
from email.message import Message
from pathlib import Path

import pytest
import requests

import pinned_http
import search_adapters


PUBLIC_IP = "93.184.216.34"


def test_transport_uses_only_public_urllib3_imports():
    source = (Path(__file__).resolve().parents[1] / "pinned_http.py").read_text(
        encoding="utf-8"
    )

    assert "urllib3._" not in source
    assert "from urllib3 import HTTPResponse as Urllib3HTTPResponse" in source


class _FakeSocket:
    def __init__(self, peer_ip=PUBLIC_IP):
        self.peer_ip = peer_ip
        self.connected_to = None
        self.timeout = None
        self.sent = []
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, sockaddr):
        self.connected_to = sockaddr

    def getpeername(self):
        return self.peer_ip, 443

    def sendall(self, payload):
        self.sent.append(payload)

    def close(self):
        self.closed = True


class _WireResponse:
    status = 200
    reason = "OK"
    version = 11

    def __init__(self, body=b"", headers=None):
        self._body = io.BytesIO(body)
        self._headers = list(headers or [])
        self.msg = Message()
        for name, value in self._headers:
            self.msg.add_header(name, value)
        self.closed = False

    def getheaders(self):
        return list(self._headers)

    def read(self, amount=None):
        return self._body.read() if amount is None else self._body.read(amount)

    def close(self):
        self.closed = True
        self._body.close()

    def isclosed(self):
        return self.closed


class _FakeConnection:
    instances = []
    wire_response = _WireResponse()

    def __init__(self, host, port=None, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.requests = []
        self.closed = False
        type(self).instances.append(self)

    def request(self, method, target, body=None, headers=None, encode_chunked=False):
        self.requests.append((method, target, body, dict(headers or {})))
        self.sock.sendall(b"HTTP request")

    def getresponse(self):
        return type(self).wire_response

    def close(self):
        self.closed = True
        if self.sock is not None:
            self.sock.close()


def _public_dns(_host, port, **_kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (PUBLIC_IP, port))]


def test_rejects_credentials_controls_and_non_http_before_dns(monkeypatch):
    calls = []
    monkeypatch.setattr(pinned_http.socket, "getaddrinfo", lambda *_a, **_k: calls.append(1))

    for url in (
        "http://user:placeholder@example.test/report",
        "https://example.test/report\r\nX-Test: injected",
        "ftp://example.test/report",
    ):
        with pytest.raises(pinned_http.UnsafeTargetError):
            pinned_http.pinned_get(url)

    assert calls == []


def test_rejects_entire_dns_answer_if_any_address_is_not_global(monkeypatch):
    dns_calls = []

    def mixed_dns(_host, port, **_kwargs):
        dns_calls.append((_host, port))
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (PUBLIC_IP, port)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.8", port)),
        ]

    monkeypatch.setattr(pinned_http.socket, "getaddrinfo", mixed_dns)
    monkeypatch.setattr(
        pinned_http.socket,
        "socket",
        lambda *_a, **_k: pytest.fail("unsafe DNS result must be rejected before connect"),
    )

    with pytest.raises(pinned_http.UnsafeTargetError, match="非公网"):
        pinned_http.pinned_get("http://public.test/report")

    assert dns_calls == [("public.test", 80)]


@pytest.mark.parametrize(
    "address",
    [
        "::ffff:127.0.0.1",
        "2002:7f00:1::",
        "2001:0000:4136:e378:8000:63bf:80ff:fffe",
        "::7f00:1",
        "64:ff9b::7f00:1",
        "64:ff9b::a00:1",
        "64:ff9b:1::7f00:1",
    ],
)
def test_rejects_ipv4_embedded_and_transition_ipv6_addresses(address):
    with pytest.raises(pinned_http.UnsafeTargetError, match="IPv4"):
        pinned_http._global_ip(address, dns_answer=True)


def test_accepts_native_global_ipv6_address():
    assert str(
        pinned_http._global_ip("2606:4700:4700::1111", dns_answer=True)
    ) == "2606:4700:4700::1111"


def test_rejects_too_many_unique_dns_addresses_before_connect(monkeypatch):
    def oversized_dns(_host, port, **_kwargs):
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (f"93.184.216.{index}", port),
            )
            for index in range(1, pinned_http._MAX_DNS_ADDRESSES + 2)
        ]

    monkeypatch.setattr(pinned_http.socket, "getaddrinfo", oversized_dns)
    monkeypatch.setattr(
        pinned_http.socket,
        "socket",
        lambda *_a, **_k: pytest.fail("oversized DNS answer must be rejected before connect"),
    )

    with pytest.raises(pinned_http.UnsafeTargetError, match="地址过多"):
        pinned_http.pinned_get("http://public.test/report")


def test_connect_attempts_share_one_monotonic_deadline(monkeypatch):
    first = _FakeSocket()

    def fail_connect(_sockaddr):
        raise OSError("unreachable")

    first.connect = fail_connect
    created = []

    def socket_factory(*_args, **_kwargs):
        created.append(1)
        if len(created) > 1:
            pytest.fail("deadline exhaustion must stop before creating another socket")
        return first

    clock = iter((100.0, 100.0, 106.0))
    monkeypatch.setattr(pinned_http.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(pinned_http.socket, "socket", socket_factory)
    addresses = [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, (PUBLIC_IP, 80), pinned_http.ipaddress.ip_address(PUBLIC_IP)),
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, ("93.184.216.35", 80), pinned_http.ipaddress.ip_address("93.184.216.35")),
    ]

    with pytest.raises(requests.ConnectTimeout, match="超时"):
        pinned_http._connect_pinned(
            addresses,
            scheme="http",
            hostname="public.test",
            timeout=5.0,
        )

    assert created == [1]
    assert first.timeout == pytest.approx(5.0)


def test_dns_rebinding_peer_is_blocked_before_any_http_bytes(monkeypatch):
    rebound_socket = _FakeSocket(peer_ip="127.0.0.1")
    _FakeConnection.instances = []
    monkeypatch.setattr(pinned_http.socket, "getaddrinfo", _public_dns)
    monkeypatch.setattr(pinned_http.socket, "socket", lambda *_a, **_k: rebound_socket)
    monkeypatch.setattr(pinned_http.http.client, "HTTPConnection", _FakeConnection)

    with pytest.raises(pinned_http.UnsafeTargetError, match="对端.*非公网"):
        pinned_http.pinned_get("http://public.test/report")

    assert rebound_socket.connected_to == (PUBLIC_IP, 80)
    assert rebound_socket.sent == []
    assert _FakeConnection.instances == []


def test_https_uses_default_ca_hostname_sni_and_tls12(monkeypatch):
    raw_socket = _FakeSocket()
    tls_socket = _FakeSocket()
    wrapped = []

    class _Context:
        check_hostname = True
        verify_mode = ssl.CERT_REQUIRED
        minimum_version = None

        def wrap_socket(self, sock, *, server_hostname):
            wrapped.append((sock, server_hostname, self.minimum_version))
            return tls_socket

    context = _Context()
    _FakeConnection.instances = []
    _FakeConnection.wire_response = _WireResponse(
        b"ok",
        [
            ("Content-Type", "text/plain; charset=utf-8"),
            ("Content-Length", "2"),
            ("Set-Cookie", "next=ready; Path=/; Secure; HttpOnly"),
        ],
    )
    monkeypatch.setattr(pinned_http.socket, "getaddrinfo", _public_dns)
    monkeypatch.setattr(pinned_http.socket, "socket", lambda *_a, **_k: raw_socket)
    monkeypatch.setattr(pinned_http.ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(pinned_http.http.client, "HTTPConnection", _FakeConnection)

    request_cookies = requests.cookies.RequestsCookieJar()
    request_cookies.set("session", "active", domain="public.test", path="/")
    response = pinned_http.pinned_get(
        "https://public.test/report?q=1",
        headers={"X-Test": "yes"},
        cookies=request_cookies,
    )
    try:
        assert wrapped == [(raw_socket, "public.test", ssl.TLSVersion.TLSv1_2)]
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED
        connection = _FakeConnection.instances[-1]
        assert connection.host == "public.test"
        assert connection.port == 443
        assert connection.requests == [
            (
                "GET",
                "/report?q=1",
                None,
                {"X-Test": "yes", "Cookie": "session=active", "Connection": "close"},
            )
        ]
        assert response.status_code == 200
        assert response.url == "https://public.test/report?q=1"
        assert response.encoding == "utf-8"
        assert response.cookies.get("next") == "ready"
        response.raise_for_status()
        assert response.text == "ok"
    finally:
        response.close()
    assert connection.closed is True


def test_https_rechecks_wrapped_peer_before_http_request(monkeypatch):
    raw_socket = _FakeSocket()
    rebound_tls_socket = _FakeSocket(peer_ip="10.0.0.9")

    class _Context:
        minimum_version = None

        def wrap_socket(self, _sock, *, server_hostname):
            assert server_hostname == "public.test"
            return rebound_tls_socket

    _FakeConnection.instances = []
    monkeypatch.setattr(pinned_http.socket, "getaddrinfo", _public_dns)
    monkeypatch.setattr(pinned_http.socket, "socket", lambda *_a, **_k: raw_socket)
    monkeypatch.setattr(pinned_http.ssl, "create_default_context", _Context)
    monkeypatch.setattr(pinned_http.http.client, "HTTPConnection", _FakeConnection)

    with pytest.raises(pinned_http.UnsafeTargetError, match="对端.*非公网"):
        pinned_http.pinned_get("https://public.test/report")

    assert rebound_tls_socket.sent == []
    assert _FakeConnection.instances == []


def test_https_certificate_failure_uses_requests_compatible_exception(monkeypatch):
    raw_socket = _FakeSocket()

    class _Context:
        minimum_version = None

        def wrap_socket(self, _sock, *, server_hostname):
            assert server_hostname == "public.test"
            raise ssl.SSLCertVerificationError(1, "certificate rejected")

    monkeypatch.setattr(pinned_http.socket, "getaddrinfo", _public_dns)
    monkeypatch.setattr(pinned_http.socket, "socket", lambda *_a, **_k: raw_socket)
    monkeypatch.setattr(pinned_http.ssl, "create_default_context", _Context)

    with pytest.raises(requests.exceptions.SSLError):
        pinned_http.pinned_get("https://public.test/report")


def test_requests_response_streams_and_decodes_gzip_with_size_limit_compatibility(monkeypatch):
    plain = (b"streamed payload " * 1000)
    compressed = gzip.compress(plain)
    fake_socket = _FakeSocket()
    _FakeConnection.instances = []
    _FakeConnection.wire_response = _WireResponse(
        compressed,
        [
            ("Content-Type", "application/octet-stream"),
            ("Content-Encoding", "gzip"),
            ("Content-Length", str(len(compressed))),
        ],
    )
    monkeypatch.setattr(pinned_http.socket, "getaddrinfo", _public_dns)
    monkeypatch.setattr(pinned_http.socket, "socket", lambda *_a, **_k: fake_socket)
    monkeypatch.setattr(pinned_http.http.client, "HTTPConnection", _FakeConnection)

    response = pinned_http.pinned_get("http://public.test/archive")
    try:
        assert isinstance(response, requests.Response)
        chunks = list(response.iter_content(chunk_size=257))
        assert b"".join(chunks) == plain
        assert len(chunks) > 1
    finally:
        response.close()

    _FakeConnection.wire_response = _WireResponse(
        compressed,
        [
            ("Content-Type", "application/octet-stream"),
            ("Content-Encoding", "gzip"),
            ("Content-Length", str(len(compressed))),
        ],
    )
    oversized = pinned_http.pinned_get("http://public.test/archive")
    try:
        with pytest.raises(RuntimeError, match="文件超过"):
            search_adapters._read_limited_response(oversized, max_bytes=len(plain) - 1)
    finally:
        oversized.close()


def test_pinned_post_serializes_json_over_the_validated_socket(monkeypatch):
    fake_socket = _FakeSocket()
    _FakeConnection.instances = []
    _FakeConnection.wire_response = _WireResponse(
        b'{"ok":true}',
        [("Content-Type", "application/json"), ("Content-Length", "11")],
    )
    monkeypatch.setattr(pinned_http.socket, "getaddrinfo", _public_dns)
    monkeypatch.setattr(pinned_http.socket, "socket", lambda *_a, **_k: fake_socket)
    monkeypatch.setattr(pinned_http.http.client, "HTTPConnection", _FakeConnection)

    response = pinned_http.pinned_post(
        "http://public.test/v1/chat",
        headers={"Authorization": "Bearer placeholder"},
        json={"prompt": "unit"},
    )
    try:
        method, target, body, headers = _FakeConnection.instances[-1].requests[-1]
        assert method == "POST"
        assert target == "/v1/chat"
        assert json.loads(body.decode("utf-8")) == {"prompt": "unit"}
        assert headers["Content-Type"] == "application/json"
        assert headers["Authorization"] == "Bearer placeholder"
        assert headers["Connection"] == "close"
        assert response.json() == {"ok": True}
    finally:
        response.close()


def test_pinned_post_rejects_user_content_length_before_dns(monkeypatch):
    monkeypatch.setattr(
        pinned_http.socket,
        "getaddrinfo",
        lambda *_a, **_k: pytest.fail("forbidden header must fail before DNS"),
    )

    with pytest.raises(pinned_http.UnsafeTargetError, match="Content-Length"):
        pinned_http.pinned_post(
            "https://public.test/v1/chat",
            headers={"Content-Length": "1"},
            json={"prompt": "unit"},
        )


def test_pinned_post_rejects_mixed_private_dns_before_request_bytes(monkeypatch):
    def mixed_dns(_host, port, **_kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (PUBLIC_IP, port)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.8", port)),
        ]

    monkeypatch.setattr(pinned_http.socket, "getaddrinfo", mixed_dns)
    monkeypatch.setattr(
        pinned_http.socket,
        "socket",
        lambda *_a, **_k: pytest.fail("mixed DNS answer must fail before connect"),
    )

    with pytest.raises(pinned_http.UnsafeTargetError, match="非公网"):
        pinned_http.pinned_post(
            "https://public.test/v1/chat",
            json={"prompt": "unit"},
        )
