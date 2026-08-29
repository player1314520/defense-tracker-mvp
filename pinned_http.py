# -*- coding: utf-8 -*-
"""Proxy-free, DNS-pinned HTTP transport for untrusted public URLs.

The security boundary is deliberately below callers' URL pre-checks: one DNS
answer is validated in full, the TCP socket connects directly to one validated
sockaddr, and the connected peer is checked before any HTTP request bytes are
sent.  Redirect handling stays with the caller so every hop crosses the same
boundary again.
"""
from __future__ import annotations

import http.client
import ipaddress
import math
import re
import socket
import ssl
import time
from collections.abc import Mapping
from http.cookiejar import CookieJar
from typing import Any
from urllib.parse import urlsplit

import requests
from requests.structures import CaseInsensitiveDict
from urllib3 import HTTPResponse as Urllib3HTTPResponse


_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
_FORBIDDEN_REQUEST_HEADERS = {
    "host",
    "proxy-authorization",
    "proxy-connection",
    "content-length",
    "transfer-encoding",
}
_MAX_DNS_ADDRESSES = 8
_IPV6_TRANSITION_NETWORKS = (
    ipaddress.ip_network("::/96"),
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
)


class UnsafeTargetError(RuntimeError):
    """The URL or resolved/connected network target is not safe to request."""


class _PinnedRawResponse(Urllib3HTTPResponse):
    """urllib3 stream that also owns the one-shot http.client connection."""

    def __init__(self, *args: Any, owner: http.client.HTTPConnection, **kwargs: Any) -> None:
        self._pinned_owner = owner
        self._pinned_owner_closed = False
        super().__init__(*args, **kwargs)

    def _close_owner(self) -> None:
        if self._pinned_owner_closed:
            return
        self._pinned_owner_closed = True
        self._pinned_owner.close()

    def close(self) -> None:
        try:
            super().close()
        finally:
            self._close_owner()

    def release_conn(self) -> None:
        try:
            super().release_conn()
        finally:
            self._close_owner()


def _validated_request(
    method: str,
    url: str,
    headers: Mapping[str, str] | None,
    cookies: CookieJar | dict[str, str] | None,
    *,
    json_body: Any = None,
) -> tuple[requests.PreparedRequest, str, str, int]:
    if not isinstance(url, str) or not url or url != url.strip():
        raise UnsafeTargetError("URL为空或包含首尾空白")
    if _CONTROL_CHARACTERS.search(url):
        raise UnsafeTargetError("URL包含控制字符")

    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise UnsafeTargetError("仅允许HTTP或HTTPS URL")
        if parsed.username is not None or parsed.password is not None:
            raise UnsafeTargetError("URL不得包含用户凭据")
        if not parsed.hostname:
            raise UnsafeTargetError("URL缺少主机名")
        parsed_port = parsed.port
    except UnsafeTargetError:
        raise
    except (UnicodeError, ValueError) as exc:
        raise UnsafeTargetError("URL格式无效") from exc

    request_headers = dict(headers or {})
    for name, value in request_headers.items():
        lowered = name.lower()
        if lowered in _FORBIDDEN_REQUEST_HEADERS:
            raise UnsafeTargetError(f"不允许覆盖请求头: {name}")
        if _CONTROL_CHARACTERS.search(name) or _CONTROL_CHARACTERS.search(str(value)):
            raise UnsafeTargetError("请求头包含控制字符")

    try:
        prepared = requests.Request(
            method,
            url,
            headers=request_headers,
            cookies=cookies,
            json=json_body if method == "POST" else None,
        ).prepare()
        normalized = urlsplit(prepared.url)
        hostname = normalized.hostname
        port = normalized.port or (443 if normalized.scheme == "https" else 80)
    except (requests.RequestException, UnicodeError, ValueError, TypeError) as exc:
        raise UnsafeTargetError("URL或请求头格式无效") from exc

    if not hostname or not (1 <= port <= 65535):
        raise UnsafeTargetError("URL主机名或端口无效")
    if parsed_port is not None and parsed_port != port:
        raise UnsafeTargetError("URL端口规范化失败")
    if normalized.scheme not in {"http", "https"}:
        raise UnsafeTargetError("仅允许HTTP或HTTPS URL")
    if normalized.username is not None or normalized.password is not None:
        raise UnsafeTargetError("URL不得包含用户凭据")

    for name in prepared.headers:
        if _CONTROL_CHARACTERS.search(name) or _CONTROL_CHARACTERS.search(str(prepared.headers[name])):
            raise UnsafeTargetError("请求头包含控制字符")
    prepared.headers["Connection"] = "close"
    return prepared, normalized.scheme, hostname, port


def _global_ip(value: str, *, dns_answer: bool) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError as exc:
        label = "DNS结果" if dns_answer else "连接对端"
        raise UnsafeTargetError(f"{label}无法验证") from exc
    if isinstance(address, ipaddress.IPv6Address) and (
        address.ipv4_mapped is not None
        or address.sixtofour is not None
        or address.teredo is not None
        or any(address in network for network in _IPV6_TRANSITION_NETWORKS)
    ):
        label = "DNS结果" if dns_answer else "连接对端"
        raise UnsafeTargetError(f"{label}不允许IPv4嵌入或转换IPv6地址")
    if not address.is_global:
        label = "目标解析包含非公网地址" if dns_answer else "连接对端是非公网地址"
        raise UnsafeTargetError(label)
    return address


_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def _resolve_global_addresses(hostname: str, port: int) -> list[tuple[int, int, int, tuple[Any, ...], _IPAddress]]:
    try:
        results = socket.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except (socket.gaierror, OSError) as exc:
        raise requests.ConnectionError("目标域名解析失败") from exc

    resolved = []
    seen = set()
    for family, socktype, proto, _canonname, sockaddr in results:
        if family not in {socket.AF_INET, socket.AF_INET6} or not sockaddr:
            raise UnsafeTargetError("DNS结果包含不支持的地址类型")
        address = _global_ip(str(sockaddr[0]), dns_answer=True)
        key = (family, socktype, proto, tuple(sockaddr))
        if key in seen:
            continue
        seen.add(key)
        if len(resolved) >= _MAX_DNS_ADDRESSES:
            raise UnsafeTargetError("DNS结果地址过多")
        resolved.append((family, socktype, proto, tuple(sockaddr), address))
    if not resolved:
        raise requests.ConnectionError("目标域名没有可连接地址")
    return resolved


def _validate_peer(sock: socket.socket, expected: _IPAddress) -> None:
    try:
        peer = sock.getpeername()
        actual = _global_ip(str(peer[0]), dns_answer=False)
    except UnsafeTargetError:
        raise
    except (AttributeError, IndexError, OSError, TypeError) as exc:
        raise UnsafeTargetError("连接对端无法验证") from exc
    if actual != expected:
        raise UnsafeTargetError("连接对端与已解析地址不一致")


def _normalized_timeout(timeout: int | float) -> float:
    try:
        value = float(timeout)
    except (TypeError, ValueError) as exc:
        raise ValueError("timeout必须是正数") from exc
    if not math.isfinite(value) or value <= 0:
        raise ValueError("timeout必须是正数")
    return value


def _connect_pinned(
    addresses: list[tuple[int, int, int, tuple[Any, ...], _IPAddress]],
    *,
    scheme: str,
    hostname: str,
    timeout: float,
) -> socket.socket:
    tls_context = None
    if scheme == "https":
        tls_context = ssl.create_default_context()
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2

    last_error: BaseException | None = None
    deadline = time.monotonic() + timeout
    for family, socktype, proto, sockaddr, expected in addresses:
        raw_sock = None
        connected_sock = None
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout("connection deadline exhausted")
            raw_sock = socket.socket(family, socktype, proto)
            raw_sock.settimeout(remaining)
            raw_sock.connect(sockaddr)
            _validate_peer(raw_sock, expected)
            connected_sock = raw_sock
            if tls_context is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise socket.timeout("connection deadline exhausted")
                raw_sock.settimeout(remaining)
                connected_sock = tls_context.wrap_socket(raw_sock, server_hostname=hostname)
                _validate_peer(connected_sock, expected)
            return connected_sock
        except UnsafeTargetError:
            if connected_sock is not None:
                connected_sock.close()
            if raw_sock is not None and raw_sock is not connected_sock:
                raw_sock.close()
            raise
        except (OSError, ssl.SSLError) as exc:
            last_error = exc
            if connected_sock is not None:
                connected_sock.close()
            if raw_sock is not None and raw_sock is not connected_sock:
                raw_sock.close()

    if isinstance(last_error, (socket.timeout, TimeoutError)):
        raise requests.ConnectTimeout("连接目标主机超时") from last_error
    if isinstance(last_error, ssl.SSLError):
        raise requests.exceptions.SSLError("目标HTTPS连接验证失败") from last_error
    raise requests.ConnectionError("无法连接目标主机") from last_error


def _to_requests_response(
    wire_response: http.client.HTTPResponse,
    *,
    owner: http.client.HTTPConnection,
    prepared: requests.PreparedRequest,
) -> requests.Response:
    # urllib3 accepts any public Mapping here and constructs its own header
    # container.  Keep this transport off urllib3's private ``_collections``
    # module so a dependency upgrade cannot silently break the SSRF boundary.
    raw_headers = CaseInsensitiveDict(wire_response.getheaders())

    raw = _PinnedRawResponse(
        body=wire_response,
        headers=raw_headers,
        status=wire_response.status,
        version=wire_response.version,
        reason=wire_response.reason,
        preload_content=False,
        decode_content=False,
        original_response=wire_response,
        request_method="GET",
        request_url=prepared.url,
        enforce_content_length=True,
        auto_close=True,
        owner=owner,
    )
    response = requests.Response()
    response.status_code = wire_response.status
    response.headers = CaseInsensitiveDict(raw_headers)
    response.url = prepared.url
    response.reason = wire_response.reason
    response.request = prepared
    response.raw = raw
    response.encoding = requests.utils.get_encoding_from_headers(response.headers)
    requests.cookies.extract_cookies_to_jar(response.cookies, prepared, raw)
    return response


def _pinned_request(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    cookies: CookieJar | dict[str, str] | None = None,
    timeout: int | float = 10,
    json_body: Any = None,
) -> requests.Response:
    """Perform one proxy-free request to a validated, DNS-pinned target.

    This function never follows redirects.  A caller that accepts redirects
    must cross this boundary again for every URL produced by ``urljoin``.
    """
    if method not in {"GET", "POST"}:
        raise ValueError("unsupported pinned HTTP method")
    prepared, scheme, hostname, port = _validated_request(
        method,
        url,
        headers,
        cookies,
        json_body=json_body,
    )
    request_timeout = _normalized_timeout(timeout)
    addresses = _resolve_global_addresses(hostname, port)
    sock = _connect_pinned(
        addresses,
        scheme=scheme,
        hostname=hostname,
        timeout=request_timeout,
    )

    connection = http.client.HTTPConnection(hostname, port=port, timeout=request_timeout)
    connection.sock = sock
    try:
        connection.request(
            method,
            prepared.path_url or "/",
            body=prepared.body,
            headers=dict(prepared.headers),
        )
        wire_response = connection.getresponse()
        return _to_requests_response(wire_response, owner=connection, prepared=prepared)
    except http.client.InvalidURL as exc:
        connection.close()
        raise UnsafeTargetError("URL请求目标无效") from exc
    except (socket.timeout, TimeoutError) as exc:
        connection.close()
        raise requests.ReadTimeout("目标响应超时") from exc
    except ssl.SSLError as exc:
        connection.close()
        raise requests.exceptions.SSLError("目标HTTPS响应失败") from exc
    except (OSError, http.client.HTTPException) as exc:
        connection.close()
        raise requests.ConnectionError("目标HTTP响应失败") from exc
    except Exception:
        connection.close()
        raise


def pinned_get(
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    cookies: CookieJar | dict[str, str] | None = None,
    timeout: int | float = 10,
) -> requests.Response:
    return _pinned_request(
        "GET",
        url,
        headers=headers,
        cookies=cookies,
        timeout=timeout,
    )


def pinned_post(
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    cookies: CookieJar | dict[str, str] | None = None,
    json: Any,
    timeout: int | float = 10,
) -> requests.Response:
    return _pinned_request(
        "POST",
        url,
        headers=headers,
        cookies=cookies,
        timeout=timeout,
        json_body=json,
    )


__all__ = ["UnsafeTargetError", "pinned_get", "pinned_post"]
