"""Fail-closed WeChat Official Account publication primitives.

This module deliberately has no scheduler and never reads credentials from
command-line arguments.  The caller supplies secrets in memory and controls
whether public delivery is enabled.
"""

from __future__ import annotations

import base64
import hashlib
from html.parser import HTMLParser
import ipaddress
import json
import os
import re
import sqlite3
import struct
import time
import uuid
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

import requests

from wechat_runtime import (
    ensure_private_file,
    reject_windows_reparse_chain,
    resolve_runtime_paths,
)

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ImportError:  # pragma: no cover - exercised by fail-closed runtime behavior
    InvalidSignature = None
    serialization = None
    Ed25519PrivateKey = None
    Ed25519PublicKey = None


API_BASE = "https://api.weixin.qq.com"


class ApiError(RuntimeError):
    """The platform rejected a request or returned an invalid response."""

    def __init__(
        self,
        message: str,
        *,
        errcode: int | None = None,
        safe_code: str = "UNKNOWN",
    ) -> None:
        super().__init__(message)
        self.errcode = errcode
        self.safe_code = safe_code


class ApprovalError(RuntimeError):
    """A public-delivery approval is absent or not bound to this content."""


class IdempotencyConflict(RuntimeError):
    """The same channel/date/edition key was reused with different content."""


class ManifestError(ValueError):
    """The publication manifest is incomplete or malformed."""


class CredentialVaultError(RuntimeError):
    """The local credential vault is unreadable or invalid."""


_TOKEN_ERRCODES = frozenset({40001, 40014, 42001})
_PROBE_ERRCODE_CATEGORIES = {
    40002: "CONFIG",
    40013: "CONFIG",
    41002: "CONFIG",
    41004: "CONFIG",
    43002: "CONFIG",
    40125: "CONFIG",
    40164: "IP_ALLOWLIST",
    45035: "IP_ALLOWLIST",
    61004: "IP_ALLOWLIST",
    48001: "PERMISSION",
    48004: "PERMISSION",
    89503: "PERMISSION",
    89506: "PERMISSION",
    89507: "PERMISSION",
    40001: "TOKEN",
    40014: "TOKEN",
    42001: "TOKEN",
    40007: "MATERIAL",
    -1: "TRANSIENT",
    45009: "QUOTA",
    45011: "QUOTA",
}
_PROBE_SAFE_CODE_CATEGORIES = {
    "MATERIAL_TOO_LARGE": "MATERIAL",
    "INVALID_IMAGE": "MATERIAL",
    "HTTP_ERROR": "UNKNOWN",
    "REQUEST_ERROR": "UNKNOWN",
    "UNEXPECTED_RESPONSE": "UNKNOWN",
    "UNKNOWN": "UNKNOWN",
}
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_MAX_DECODED_IMAGE_BYTES = 32 * 1024 * 1024


def _normalize_api_errcode(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"-?[0-9]{1,10}", value):
        try:
            return int(value)
        except ValueError:  # pragma: no cover - guarded by the expression above
            return None
    return None


def _raise_for_api_payload(data: Any, endpoint: str) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ApiError(
            f"WeChat API {endpoint} returned an invalid payload",
            safe_code="UNEXPECTED_RESPONSE",
        )
    if "errcode" in data:
        errcode = _normalize_api_errcode(data.get("errcode"))
        if errcode is None:
            raise ApiError(
                f"WeChat API {endpoint} returned an invalid errcode",
                safe_code="UNEXPECTED_RESPONSE",
            )
        if errcode != 0:
            # Never include errmsg: platforms sometimes echo request values.
            raise ApiError(
                f"WeChat API {endpoint} failed with errcode {errcode}",
                errcode=errcode,
                safe_code=str(errcode),
            )
    return data


def _probe_result() -> dict[str, Any]:
    return {
        "status": "FAILED",
        "token_ok": False,
        "draft_count_ok": False,
        "total_count": None,
        "cover_ok": False,
        "cover_kind": None,
        "code": "UNKNOWN",
        "category": "UNKNOWN",
    }


def _apply_probe_failure(result: dict[str, Any], error: ApiError) -> dict[str, Any]:
    if error.errcode is not None:
        code = str(error.errcode)
        category = _PROBE_ERRCODE_CATEGORIES.get(error.errcode, "UNKNOWN")
    else:
        code = error.safe_code if error.safe_code in _PROBE_SAFE_CODE_CATEGORIES else "UNKNOWN"
        category = _PROBE_SAFE_CODE_CATEGORIES.get(code, "UNKNOWN")
    result.update({"status": "FAILED", "code": code, "category": category})
    if category == "TOKEN":
        result["token_ok"] = False
    return result


def _invalid_image() -> ApiError:
    return ApiError("WeChat cover material is not a valid supported image", safe_code="INVALID_IMAGE")


def _validate_png(payload: bytes) -> None:
    if not payload.startswith(_PNG_SIGNATURE):
        raise _invalid_image()
    offset = len(_PNG_SIGNATURE)
    width = height = bit_depth = color_type = interlace = None
    compressed = bytearray()
    saw_header = saw_data = saw_end = False
    palette_seen = False

    while offset < len(payload):
        if len(payload) - offset < 12:
            raise _invalid_image()
        length = struct.unpack(">I", payload[offset : offset + 4])[0]
        chunk_type = payload[offset + 4 : offset + 8]
        chunk_end = offset + 12 + length
        if chunk_end > len(payload):
            raise _invalid_image()
        chunk_data = payload[offset + 8 : offset + 8 + length]
        stored_crc = struct.unpack(">I", payload[offset + 8 + length : chunk_end])[0]
        actual_crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
        if stored_crc != actual_crc:
            raise _invalid_image()

        if not saw_header:
            if chunk_type != b"IHDR" or length != 13:
                raise _invalid_image()
            width, height, bit_depth, color_type, compression, filter_method, interlace = (
                struct.unpack(">IIBBBBB", chunk_data)
            )
            if (
                width <= 0
                or height <= 0
                or width * height > 40_000_000
                or compression != 0
                or filter_method != 0
                or interlace != 0
            ):
                raise _invalid_image()
            valid_depths = {
                0: {1, 2, 4, 8, 16},
                2: {8, 16},
                3: {1, 2, 4, 8},
                4: {8, 16},
                6: {8, 16},
            }
            if color_type not in valid_depths or bit_depth not in valid_depths[color_type]:
                raise _invalid_image()
            saw_header = True
        elif chunk_type == b"IHDR":
            raise _invalid_image()
        elif chunk_type == b"PLTE":
            if saw_data or length == 0 or length % 3 or length > 768:
                raise _invalid_image()
            palette_seen = True
        elif chunk_type == b"IDAT":
            saw_data = True
            compressed.extend(chunk_data)
        elif chunk_type == b"IEND":
            if length != 0 or not saw_data or chunk_end != len(payload):
                raise _invalid_image()
            saw_end = True
            offset = chunk_end
            break
        elif chunk_type[:1].isupper():
            raise _invalid_image()
        offset = chunk_end

    if not saw_header or not saw_data or not saw_end:
        raise _invalid_image()
    if color_type == 3 and not palette_seen:
        raise _invalid_image()

    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[int(color_type)]
    row_bytes = (int(width) * channels * int(bit_depth) + 7) // 8
    expected_size = (row_bytes + 1) * int(height)
    if expected_size > _MAX_DECODED_IMAGE_BYTES:
        raise _invalid_image()
    try:
        decoder = zlib.decompressobj()
        decoded = decoder.decompress(bytes(compressed), expected_size + 1)
    except zlib.error as exc:
        raise _invalid_image() from exc
    if (
        len(decoded) != expected_size
        or decoder.unconsumed_tail
        or decoder.unused_data
        or not decoder.eof
    ):
        raise _invalid_image()
    stride = row_bytes + 1
    if any(decoded[row] > 4 for row in range(0, len(decoded), stride)):
        raise _invalid_image()


def _validate_jpeg(payload: bytes) -> None:
    if len(payload) < 8 or not payload.startswith(b"\xff\xd8") or not payload.endswith(b"\xff\xd9"):
        raise _invalid_image()
    offset = 2
    saw_frame = False
    saw_scan = False
    frame_markers = {
        0xC0,
        0xC1,
        0xC2,
        0xC3,
        0xC5,
        0xC6,
        0xC7,
        0xC9,
        0xCA,
        0xCB,
        0xCD,
        0xCE,
        0xCF,
    }
    while offset < len(payload) - 2:
        if payload[offset] != 0xFF:
            raise _invalid_image()
        while offset < len(payload) and payload[offset] == 0xFF:
            offset += 1
        if offset >= len(payload):
            raise _invalid_image()
        marker = payload[offset]
        offset += 1
        if marker == 0xD9:
            break
        if marker in {0x01, *range(0xD0, 0xD8)}:
            continue
        if offset + 2 > len(payload):
            raise _invalid_image()
        segment_length = struct.unpack(">H", payload[offset : offset + 2])[0]
        if segment_length < 2 or offset + segment_length > len(payload):
            raise _invalid_image()
        segment = payload[offset + 2 : offset + segment_length]
        if marker in frame_markers:
            if len(segment) < 6:
                raise _invalid_image()
            height, width = struct.unpack(">HH", segment[1:5])
            if height <= 0 or width <= 0 or height * width > 40_000_000:
                raise _invalid_image()
            saw_frame = True
        if marker == 0xDA:
            saw_scan = True
            scan_start = offset + segment_length
            if scan_start >= len(payload) - 2:
                raise _invalid_image()
            break
        offset += segment_length
    if not saw_frame or not saw_scan:
        raise _invalid_image()


def _validated_image_kind(payload: bytes) -> str:
    if payload.startswith(_PNG_SIGNATURE):
        _validate_png(payload)
        return "png"
    if payload.startswith(b"\xff\xd8"):
        _validate_jpeg(payload)
        return "jpeg"
    raise _invalid_image()


class WechatCredentialVault:
    """Persist one DPAPI-protected credential JSON package for this user."""

    _ALLOWED_FIELDS = {
        "app_id",
        "app_secret",
        "thumb_media_id",
        "approval_public_key",
    }

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        protector: Any | None = None,
        file_security: Any = ensure_private_file,
    ) -> None:
        if path is None:
            path = resolve_runtime_paths().vault_path
        self.path = Path(path)
        if protector is None:
            from v9.supabase_client import WindowsDpapiProtector

            protector = WindowsDpapiProtector()
        self.protector = protector
        self.file_security = file_security

    def save(self, credentials: Mapping[str, Any]) -> None:
        unknown = set(credentials) - self._ALLOWED_FIELDS
        if unknown:
            raise ValueError(f"unsupported credential fields: {sorted(unknown)}")
        normalized = {
            name: (
                str(credentials.get(name, ""))
                if name == "approval_public_key"
                else str(credentials.get(name, "")).strip()
            )
            for name in sorted(self._ALLOWED_FIELDS)
            if credentials.get(name) is not None
        }
        if not normalized.get("app_id") or not normalized.get("app_secret"):
            raise ValueError("app_id and app_secret are required")
        if "PRIVATE KEY" in normalized.get("approval_public_key", "").upper():
            raise ValueError("private keys are forbidden")
        plaintext = _canonical_json({"schema": 1, "credentials": normalized}).encode("utf-8")
        try:
            protected = self.protector.protect(plaintext)
        except Exception as exc:
            raise CredentialVaultError("credential protection failed") from exc
        envelope = {
            "schema": 1,
            "protected_payload": base64.b64encode(protected).decode("ascii"),
        }
        reject_windows_reparse_chain(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(f"{self.path.suffix}.tmp")
        reject_windows_reparse_chain(temporary)
        temporary.write_text(_canonical_json(envelope), encoding="utf-8")
        ensure_private_file(temporary)
        temporary.replace(self.path)
        ensure_private_file(self.path)

    def load(self) -> dict[str, str] | None:
        reject_windows_reparse_chain(self.path)
        if not self.path.is_file():
            return None
        self.file_security(self.path)
        try:
            envelope = json.loads(self.path.read_text(encoding="utf-8"))
            if envelope.get("schema") != 1:
                raise ValueError("unsupported schema")
            protected = base64.b64decode(envelope["protected_payload"], validate=True)
            plaintext = self.protector.unprotect(protected)
            payload = json.loads(plaintext.decode("utf-8"))
            if payload.get("schema") != 1 or not isinstance(payload.get("credentials"), dict):
                raise ValueError("invalid payload")
            credentials = payload["credentials"]
            if set(credentials) - self._ALLOWED_FIELDS:
                raise ValueError("unexpected fields")
            if not credentials.get("app_id") or not credentials.get("app_secret"):
                raise ValueError("missing credentials")
            if not all(isinstance(value, str) for value in credentials.values()):
                raise ValueError("invalid credential value")
            if "PRIVATE KEY" in credentials.get("approval_public_key", "").upper():
                raise ValueError("private keys are forbidden")
        except Exception as exc:
            raise CredentialVaultError("credential vault could not be opened") from exc
        return dict(credentials)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def compute_manifest_hashes(manifest: Mapping[str, Any]) -> dict[str, str]:
    """Return approval hashes; the mutable approval envelope is excluded."""

    content = {
        "channel": manifest.get("channel"),
        "publication_date": manifest.get("publication_date"),
        "edition": manifest.get("edition"),
        "delivery": manifest.get("delivery"),
        "article": manifest.get("article"),
    }
    return {
        "content_sha256": _sha256(content),
        "source_sha256": _sha256(manifest.get("sources", [])),
    }


def _approval_scope(manifest: Mapping[str, Any]) -> str:
    return ":".join(
        [
            "wechat-publication-v1",
            str(manifest.get("channel", "")),
            str(manifest.get("publication_date", "")),
            str(manifest.get("edition", "")),
            str(manifest.get("delivery", "")),
        ]
    )


def _approval_time(
    raw_value: Any,
    *,
    now: datetime | None = None,
    max_age: timedelta = timedelta(hours=24),
) -> datetime:
    if not isinstance(raw_value, str) or not raw_value.strip():
        raise ApprovalError("approval timestamp is missing or invalid")
    try:
        approved_at = datetime.fromisoformat(raw_value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApprovalError("approval timestamp is missing or invalid") from exc
    if approved_at.tzinfo is None or approved_at.utcoffset() is None:
        raise ApprovalError("approval timestamp must include a UTC offset")
    approved_at = approved_at.astimezone(timezone.utc)
    reference = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if approved_at > reference:
        raise ApprovalError("approval timestamp may not be in the future")
    if reference - approved_at > max_age:
        raise ApprovalError("approval has expired")
    return approved_at


def _load_approval_private_key(value: Any) -> Any:
    if Ed25519PrivateKey is None or serialization is None:
        raise ApprovalError("asymmetric approval signing is unavailable")
    if isinstance(value, Ed25519PrivateKey):
        return value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
    elif isinstance(value, bytes):
        encoded = value
    else:
        raise ApprovalError("approval private key is invalid")
    try:
        key = serialization.load_pem_private_key(encoded, password=None)
    except (TypeError, ValueError) as exc:
        raise ApprovalError("approval private key is invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ApprovalError("approval private key must use Ed25519")
    return key


def _load_approval_public_key(value: Any) -> Any:
    if Ed25519PublicKey is None or serialization is None:
        raise ApprovalError("asymmetric approval verification is unavailable")
    if isinstance(value, Ed25519PublicKey):
        return value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
    elif isinstance(value, bytes):
        encoded = value
    else:
        raise ApprovalError("approval public key is invalid")
    try:
        key = serialization.load_pem_public_key(encoded)
    except (TypeError, ValueError) as exc:
        raise ApprovalError("approval public key is invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ApprovalError("approval public key must use Ed25519")
    return key


def build_approval(
    manifest: Mapping[str, Any], approval_private_key: Any, *, approved_at: str | None = None
) -> dict[str, str]:
    """Sign one reviewed manifest; automated publication never calls this helper."""

    timestamp = approved_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    _approval_time(timestamp)
    envelope = {
        "algorithm": "Ed25519",
        "scope": _approval_scope(manifest),
        **compute_manifest_hashes(manifest),
        "approved_at": timestamp,
    }
    private_key = _load_approval_private_key(approval_private_key)
    signature = private_key.sign(_canonical_json(envelope).encode("utf-8"))
    envelope["signature"] = base64.b64encode(signature).decode("ascii")
    return envelope


def _verify_approval(
    manifest: Mapping[str, Any], approval_public_key: Any, *, max_age: timedelta
) -> None:
    if not approval_public_key:
        raise ApprovalError("public delivery requires an approval public key")
    approval = manifest.get("approval")
    if not isinstance(approval, Mapping):
        raise ApprovalError("public delivery requires a signed approval")
    hashes = compute_manifest_hashes(manifest)
    unsigned = {
        "algorithm": "Ed25519",
        "scope": _approval_scope(manifest),
        "content_sha256": hashes["content_sha256"],
        "source_sha256": hashes["source_sha256"],
        "approved_at": approval.get("approved_at"),
    }
    for key, expected in unsigned.items():
        if not isinstance(expected, str) or approval.get(key) != expected:
            raise ApprovalError("approval is not bound to this publication manifest")
    _approval_time(unsigned["approved_at"], max_age=max_age)
    try:
        signature = base64.b64decode(str(approval.get("signature", "")), validate=True)
    except (ValueError, TypeError) as exc:
        raise ApprovalError("approval signature is invalid") from exc
    if len(signature) != 64:
        raise ApprovalError("approval signature is invalid")
    public_key = _load_approval_public_key(approval_public_key)
    try:
        public_key.verify(signature, _canonical_json(unsigned).encode("utf-8"))
    except Exception as exc:
        if InvalidSignature is not None and isinstance(exc, InvalidSignature):
            raise ApprovalError("approval signature is invalid") from exc
        raise ApprovalError("approval signature verification failed") from exc


_BLOCKED_SOURCE_DOMAINS = ("zhihu.com", "weixin.qq.com", "baidu.com")
_LOCAL_PATH = re.compile(r"(?:file\s*:|(?<![a-z0-9])(?:[a-z]:[\\/]|\\\\))", re.IGNORECASE)
_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f]")
_NONSTANDARD_NUMERIC_HOST = re.compile(
    r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*\Z",
    re.IGNORECASE,
)


def _validate_source_url(
    raw_url: Any,
    *,
    https_only: bool = False,
    allow_empty: bool = False,
    field_name: str = "source URL",
) -> None:
    if allow_empty and isinstance(raw_url, str) and not raw_url.strip():
        return
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ManifestError(f"{field_name} must include a public URL")
    url = raw_url.strip()
    if "\\" in url or _CONTROL_OR_SPACE.search(url):
        raise ManifestError(f"{field_name} may not contain whitespace or backslashes")
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").rstrip(".").lower()
        port = parsed.port
    except ValueError as exc:
        raise ManifestError(f"{field_name} is invalid") from exc
    allowed_schemes = {"https"} if https_only else {"http", "https"}
    if parsed.scheme.lower() not in allowed_schemes or not host:
        requirement = "HTTPS" if https_only else "public http(s)"
        raise ManifestError(f"{field_name} must use {requirement}")
    if parsed.username is not None or parsed.password is not None:
        raise ManifestError(f"{field_name} may not contain userinfo")
    if port is not None and not (1 <= port <= 65535):
        raise ManifestError(f"{field_name} port is invalid")
    if any(host == blocked or host.endswith(f".{blocked}") for blocked in _BLOCKED_SOURCE_DOMAINS):
        raise ManifestError(f"{field_name} uses a disabled domain")
    if _NONSTANDARD_NUMERIC_HOST.fullmatch(host):
        raise ManifestError(f"{field_name} must not use a numeric host alias")
    if (
        host == "localhost"
        or host.endswith(".localhost")
        or host.endswith(".local")
        or host.endswith(".internal")
        or host.endswith(".lan")
        or host.endswith(".home")
    ):
        raise ManifestError(f"{field_name} must not reference a local host")
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise ManifestError(f"{field_name} must reference a public address")


class _WechatHtmlPolicy(HTMLParser):
    _ALLOWED_TAGS = {
        "a",
        "b",
        "blockquote",
        "br",
        "em",
        "h1",
        "h2",
        "h3",
        "h4",
        "i",
        "img",
        "li",
        "ol",
        "p",
        "s",
        "section",
        "span",
        "strong",
        "u",
        "ul",
    }
    _ALLOWED_ATTRIBUTES = {
        "a": {"href", "title"},
        "img": {"src", "alt", "title", "width", "height"},
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)

    def _validate_tag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag not in self._ALLOWED_TAGS:
            raise ManifestError("article HTML contains a disallowed element")
        allowed = self._ALLOWED_ATTRIBUTES.get(tag, set())
        for raw_name, raw_value in attrs:
            name = raw_name.lower()
            if name not in allowed or name.startswith("on") or name == "style":
                raise ManifestError("article HTML contains a disallowed attribute")
            value = raw_value or ""
            if name in {"href", "src"}:
                _validate_source_url(
                    value,
                    https_only=True,
                    field_name=f"HTML {name}",
                )
            elif name in {"width", "height"} and (
                not value.isdecimal() or not 1 <= int(value) <= 4096
            ):
                raise ManifestError("article HTML image dimensions are invalid")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._validate_tag(tag, attrs)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._validate_tag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() not in self._ALLOWED_TAGS:
            raise ManifestError("article HTML contains a disallowed element")

    def handle_comment(self, data: str) -> None:
        raise ManifestError("article HTML comments are not allowed")

    def handle_decl(self, decl: str) -> None:
        raise ManifestError("article HTML declarations are not allowed")

    def handle_pi(self, data: str) -> None:
        raise ManifestError("article HTML processing instructions are not allowed")

    def unknown_decl(self, data: str) -> None:
        raise ManifestError("article HTML declarations are not allowed")


def _validate_article_html(content: str) -> None:
    if _LOCAL_PATH.search(content) or "\x00" in content:
        raise ManifestError("article HTML contains a local path or control character")
    parser = _WechatHtmlPolicy()
    try:
        parser.feed(content)
        parser.close()
    except ManifestError:
        raise
    except Exception as exc:
        raise ManifestError("article HTML is malformed") from exc


def validate_manifest(manifest: Mapping[str, Any], *, require_thumb: bool = True) -> None:
    for name in ("channel", "publication_date", "edition", "delivery"):
        if not isinstance(manifest.get(name), str) or not str(manifest[name]).strip():
            raise ManifestError(f"missing manifest field: {name}")
    try:
        datetime.strptime(str(manifest["publication_date"]), "%Y-%m-%d")
    except ValueError as exc:
        raise ManifestError("publication_date must use YYYY-MM-DD") from exc
    if manifest["delivery"] not in {"draft", "publish", "mass"}:
        raise ManifestError("delivery must be draft, publish, or mass")
    article = manifest.get("article")
    if not isinstance(article, Mapping):
        raise ManifestError("article must be an object")
    required_article_fields = ["title", "digest", "content"]
    if require_thumb:
        required_article_fields.append("thumb_media_id")
    for name in required_article_fields:
        if not isinstance(article.get(name), str) or not str(article[name]).strip():
            raise ManifestError(f"missing article field: {name}")
    if len(str(article["title"]).strip()) > 32:
        raise ManifestError("article title exceeds 32 characters")
    if len(str(article["digest"]).strip()) > 120:
        raise ManifestError("article digest exceeds 120 characters")
    content = str(article["content"])
    _validate_article_html(content)
    _validate_source_url(
        article.get("content_source_url", ""),
        https_only=True,
        allow_empty=True,
        field_name="content_source_url",
    )
    sources = manifest.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ManifestError("at least one source is required")
    for source in sources:
        if not isinstance(source, Mapping):
            raise ManifestError("every source must be an object")
        _validate_source_url(source.get("url"))


class WeChatApiClient:
    """Small server-side client for the official publication endpoints."""

    def __init__(
        self,
        app_id: str,
        app_secret: str,
        *,
        session: Any | None = None,
        timeout: float = 20,
    ) -> None:
        if not app_id or not app_secret:
            raise ValueError("WeChat app id and secret are required")
        self._app_id = app_id
        self._app_secret = app_secret
        self.session = session or requests.Session()
        self.timeout = timeout
        self._token: str | None = None
        self._token_deadline = 0.0

    def _post_raw(
        self,
        endpoint: str,
        payload: Mapping[str, Any],
        *,
        authenticated: bool,
    ) -> dict[str, Any]:
        params = None
        if authenticated:
            params = {"access_token": self._access_token()}
        try:
            response = self.session.post(
                f"{API_BASE}{endpoint}",
                json=dict(payload),
                params=params,
                timeout=self.timeout,
                allow_redirects=False,
            )
        except Exception as exc:
            raise ApiError(
                f"WeChat API request failed at {endpoint}",
                safe_code="REQUEST_ERROR",
            ) from exc
        if int(getattr(response, "status_code", 0)) != 200:
            raise ApiError(
                f"WeChat API {endpoint} returned a non-success HTTP status",
                safe_code="HTTP_ERROR",
            )
        try:
            data = response.json()
        except Exception as exc:
            raise ApiError(
                f"WeChat API {endpoint} returned invalid JSON",
                safe_code="UNEXPECTED_RESPONSE",
            ) from exc
        return _raise_for_api_payload(data, endpoint)

    def _access_token(self) -> str:
        now = time.monotonic()
        if self._token and now < self._token_deadline:
            return self._token
        data = self._post_raw(
            "/cgi-bin/stable_token",
            {
                "grant_type": "client_credential",
                "appid": self._app_id,
                "secret": self._app_secret,
                "force_refresh": False,
            },
            authenticated=False,
        )
        token = data.get("access_token")
        if not isinstance(token, str) or not token:
            raise ApiError(
                "WeChat stable_token response omitted access_token",
                safe_code="UNEXPECTED_RESPONSE",
            )
        try:
            expires_in = max(60, int(data.get("expires_in", 7200)))
        except (TypeError, ValueError):
            expires_in = 7200
        self._token = token
        self._token_deadline = now + max(30, expires_in - 300)
        return token

    def _probe_draft_count(self, access_token: str) -> int:
        endpoint = "/cgi-bin/draft/count"
        try:
            response = self.session.get(
                f"{API_BASE}{endpoint}",
                params={"access_token": access_token},
                timeout=self.timeout,
                allow_redirects=False,
            )
        except Exception as exc:
            raise ApiError(
                f"WeChat API request failed at {endpoint}",
                safe_code="REQUEST_ERROR",
            ) from exc
        try:
            if int(getattr(response, "status_code", 0)) != 200:
                raise ApiError(
                    f"WeChat API {endpoint} returned a non-success HTTP status",
                    safe_code="HTTP_ERROR",
                )
            try:
                data = response.json()
            except Exception as exc:
                raise ApiError(
                    f"WeChat API {endpoint} returned invalid JSON",
                    safe_code="UNEXPECTED_RESPONSE",
                ) from exc
            data = _raise_for_api_payload(data, endpoint)
            total_count = data.get("total_count")
            if isinstance(total_count, bool) or not isinstance(total_count, int) or total_count < 0:
                raise ApiError(
                    "WeChat draft/count response omitted a valid total_count",
                    safe_code="UNEXPECTED_RESPONSE",
                )
            return total_count
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()

    def _probe_cover_kind(
        self,
        access_token: str,
        media_id: str,
        *,
        max_material_bytes: int,
    ) -> str:
        endpoint = "/cgi-bin/material/get_material"
        try:
            response = self.session.post(
                f"{API_BASE}{endpoint}",
                params={"access_token": access_token},
                json={"media_id": media_id},
                timeout=self.timeout,
                stream=True,
                allow_redirects=False,
            )
        except Exception as exc:
            raise ApiError(
                f"WeChat API request failed at {endpoint}",
                safe_code="REQUEST_ERROR",
            ) from exc
        try:
            if int(getattr(response, "status_code", 0)) != 200:
                raise ApiError(
                    f"WeChat API {endpoint} returned a non-success HTTP status",
                    safe_code="HTTP_ERROR",
                )
            headers = getattr(response, "headers", {}) or {}
            declared_length = headers.get("Content-Length")
            if declared_length is not None:
                try:
                    if int(declared_length) > max_material_bytes:
                        raise ApiError(
                            "WeChat cover material exceeds the read limit",
                            safe_code="MATERIAL_TOO_LARGE",
                        )
                except (TypeError, ValueError) as exc:
                    raise ApiError(
                        "WeChat material response has an invalid Content-Length",
                        safe_code="UNEXPECTED_RESPONSE",
                    ) from exc

            body = bytearray()
            try:
                chunks = response.iter_content(chunk_size=64 * 1024)
                for chunk in chunks:
                    if not chunk:
                        continue
                    if not isinstance(chunk, (bytes, bytearray)):
                        raise ApiError(
                            "WeChat material response returned a non-binary chunk",
                            safe_code="UNEXPECTED_RESPONSE",
                        )
                    if len(body) + len(chunk) > max_material_bytes:
                        raise ApiError(
                            "WeChat cover material exceeds the read limit",
                            safe_code="MATERIAL_TOO_LARGE",
                        )
                    body.extend(chunk)
            except ApiError:
                raise
            except Exception as exc:
                raise ApiError(
                    "WeChat material response could not be read",
                    safe_code="REQUEST_ERROR",
                ) from exc

            content_type = str(headers.get("Content-Type", "")).lower()
            stripped = bytes(body).lstrip()
            if "json" in content_type or stripped.startswith(b"{"):
                try:
                    data = json.loads(bytes(body).decode("utf-8"))
                except (UnicodeError, json.JSONDecodeError) as exc:
                    raise ApiError(
                        "WeChat material endpoint returned invalid JSON",
                        safe_code="UNEXPECTED_RESPONSE",
                    ) from exc
                _raise_for_api_payload(data, endpoint)
                raise ApiError(
                    "WeChat material endpoint returned JSON instead of an image",
                    safe_code="UNEXPECTED_RESPONSE",
                )
            return _validated_image_kind(bytes(body))
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()

    def probe_account(
        self,
        thumb_media_id: str,
        *,
        max_material_bytes: int = 8 * 1024 * 1024,
    ) -> dict[str, Any]:
        """Probe token, draft count, and one cover without mutating remote state."""

        if not isinstance(thumb_media_id, str) or not thumb_media_id.strip():
            raise ValueError("thumb_media_id is required")
        if (
            isinstance(max_material_bytes, bool)
            or not isinstance(max_material_bytes, int)
            or max_material_bytes <= 0
            or max_material_bytes > 8 * 1024 * 1024
        ):
            raise ValueError("max_material_bytes must be between 1 byte and 8 MiB")

        result = _probe_result()
        try:
            token = self._access_token()
        except ApiError as exc:
            return _apply_probe_failure(result, exc)
        result["token_ok"] = True
        refresh_used = False

        def read_with_one_token_refresh(operation: Any) -> Any:
            nonlocal refresh_used, token
            try:
                return operation(token)
            except ApiError as exc:
                if exc.errcode not in _TOKEN_ERRCODES or refresh_used:
                    raise
                refresh_used = True
                self._token = None
                self._token_deadline = 0.0
                try:
                    token = self._access_token()
                except ApiError:
                    result["token_ok"] = False
                    raise
                return operation(token)

        try:
            result["total_count"] = read_with_one_token_refresh(self._probe_draft_count)
            result["draft_count_ok"] = True
        except ApiError as exc:
            return _apply_probe_failure(result, exc)

        try:
            result["cover_kind"] = read_with_one_token_refresh(
                lambda current_token: self._probe_cover_kind(
                    current_token,
                    thumb_media_id,
                    max_material_bytes=max_material_bytes,
                )
            )
            result["cover_ok"] = True
        except ApiError as exc:
            return _apply_probe_failure(result, exc)

        result.update({"status": "OK", "code": "OK", "category": "OK"})
        return result

    def add_draft(self, article: Mapping[str, Any]) -> dict[str, Any]:
        data = self._post_raw(
            "/cgi-bin/draft/add", {"articles": [dict(article)]}, authenticated=True
        )
        if not isinstance(data.get("media_id"), str) or not data["media_id"]:
            raise ApiError("WeChat draft/add response omitted media_id")
        return data

    def submit_publish(self, media_id: str) -> dict[str, Any]:
        data = self._post_raw(
            "/cgi-bin/freepublish/submit", {"media_id": media_id}, authenticated=True
        )
        if not isinstance(data.get("publish_id"), str) or not data["publish_id"]:
            raise ApiError("WeChat freepublish/submit response omitted publish_id")
        return data

    def get_publish_status(self, publish_id: str) -> dict[str, Any]:
        data = self._post_raw(
            "/cgi-bin/freepublish/get", {"publish_id": publish_id}, authenticated=True
        )
        if not isinstance(data.get("publish_status"), int):
            raise ApiError("WeChat freepublish/get response omitted publish_status")
        return data

    def mass_send_all(self, media_id: str, clientmsgid: str) -> dict[str, Any]:
        data = self._post_raw(
            "/cgi-bin/message/mass/sendall",
            {
                "filter": {"is_to_all": True},
                "mpnews": {"media_id": media_id},
                "msgtype": "mpnews",
                "send_ignore_reprint": 0,
                "clientmsgid": clientmsgid,
            },
            authenticated=True,
        )
        if data.get("msg_id") in (None, ""):
            raise ApiError("WeChat message/mass/sendall response omitted msg_id")
        return data

    def mass_get(self, msg_id: int | str) -> dict[str, Any]:
        request_msg_id: int | str = msg_id
        if isinstance(msg_id, str) and msg_id.isdecimal():
            request_msg_id = int(msg_id)
        data = self._post_raw(
            "/cgi-bin/message/mass/get", {"msg_id": request_msg_id}, authenticated=True
        )
        if not isinstance(data.get("msg_status"), str) or not data["msg_status"]:
            raise ApiError("WeChat message/mass/get response omitted msg_status")
        return data


class PublicationLedger:
    """SQLite idempotency ledger keyed by channel/date/edition."""

    _UPDATE_FIELDS = {
        "state",
        "draft_media_id",
        "publish_id",
        "msg_id",
        "clientmsgid",
        "result_json",
        "operation_owner",
        "operation_kind",
        "lease_until",
    }

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        reject_windows_reparse_chain(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            ensure_private_file(self.path)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS publications (
                    channel TEXT NOT NULL,
                    publication_date TEXT NOT NULL,
                    edition TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
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
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (channel, publication_date, edition)
                )
                """
            )
            columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(publications)").fetchall()
            }
            for name, declaration in (
                ("operation_owner", "TEXT"),
                ("operation_kind", "TEXT"),
                ("lease_until", "REAL"),
            ):
                if name not in columns:
                    connection.execute(
                        f"ALTER TABLE publications ADD COLUMN {name} {declaration}"
                    )
        ensure_private_file(self.path)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    @staticmethod
    def _key(manifest: Mapping[str, Any]) -> tuple[str, str, str]:
        return (
            str(manifest["channel"]),
            str(manifest["publication_date"]),
            str(manifest["edition"]),
        )

    def reserve(
        self,
        manifest: Mapping[str, Any],
        *,
        state: str = "review_pending",
        allow_review_update: bool = False,
    ) -> dict[str, Any]:
        hashes = compute_manifest_hashes(manifest)
        key = self._key(manifest)
        now = datetime.now().astimezone().isoformat(timespec="seconds")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM publications WHERE channel=? AND publication_date=? AND edition=?",
                key,
            ).fetchone()
            if row is not None:
                record = dict(row)
                if (
                    record["content_sha256"] != hashes["content_sha256"]
                    or record["source_sha256"] != hashes["source_sha256"]
                ):
                    if allow_review_update and record["state"] == "review_pending":
                        connection.execute(
                            """
                            UPDATE publications
                            SET content_sha256=?, source_sha256=?, updated_at=?
                            WHERE channel=? AND publication_date=? AND edition=?
                            """,
                            (
                                hashes["content_sha256"],
                                hashes["source_sha256"],
                                now,
                                *key,
                            ),
                        )
                        record["content_sha256"] = hashes["content_sha256"]
                        record["source_sha256"] = hashes["source_sha256"]
                        record["updated_at"] = now
                        return record
                    raise IdempotencyConflict(
                        "publication key already exists with different content or sources"
                    )
                return record
            connection.execute(
                """
                INSERT INTO publications (
                    channel, publication_date, edition, content_sha256,
                    source_sha256, state, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (*key, hashes["content_sha256"], hashes["source_sha256"], state, now, now),
            )
        return self.get(*key)

    def claim_submission(
        self,
        manifest: Mapping[str, Any],
        *,
        operation: str,
        owner: str,
        lease_seconds: float,
    ) -> dict[str, Any]:
        if operation not in {"draft", "publish", "mass"}:
            raise ValueError("unsupported submission operation")
        if not owner:
            raise ValueError("submission owner is required")
        now_epoch = time.time()
        lease_until = now_epoch + max(1.0, float(lease_seconds))
        now_text = datetime.now().astimezone().isoformat(timespec="seconds")
        key = self._key(manifest)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM publications WHERE channel=? AND publication_date=? AND edition=?",
                key,
            ).fetchone()
            if row is None:
                raise KeyError(key)
            record = dict(row)
            current_owner = str(record.get("operation_owner") or "")
            current_operation = str(record.get("operation_kind") or operation)
            current_lease = float(record.get("lease_until") or 0)
            uncertain_state = str(record.get("state") or "").endswith(
                "_submission_uncertain"
            )
            if uncertain_state or (current_owner and current_lease <= now_epoch):
                return {
                    "status": "submission_uncertain",
                    "operation": current_operation,
                }
            if current_owner:
                return {"status": "in_progress", "operation": current_operation}
            cursor = connection.execute(
                """
                UPDATE publications
                SET state=?, operation_owner=?, operation_kind=?, lease_until=?, updated_at=?
                WHERE channel=? AND publication_date=? AND edition=?
                  AND operation_owner IS NULL
                """,
                (
                    f"{operation}_submitting",
                    owner,
                    operation,
                    lease_until,
                    now_text,
                    *key,
                ),
            )
            if cursor.rowcount != 1:
                return {"status": "in_progress", "operation": operation}
        return {"status": "acquired", "operation": operation}

    def complete_submission(
        self,
        manifest: Mapping[str, Any],
        *,
        operation: str,
        owner: str,
        state: str,
        **values: Any,
    ) -> dict[str, Any]:
        unknown = set(values) - self._UPDATE_FIELDS
        if unknown:
            raise ValueError(f"unsupported ledger fields: {sorted(unknown)}")
        fields = {
            **values,
            "state": state,
            "operation_owner": None,
            "operation_kind": None,
            "lease_until": None,
            "updated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        }
        assignments = ", ".join(f"{name}=?" for name in fields)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                f"""
                UPDATE publications SET {assignments}
                WHERE channel=? AND publication_date=? AND edition=?
                  AND operation_owner=? AND operation_kind=?
                """,
                (
                    *fields.values(),
                    *self._key(manifest),
                    owner,
                    operation,
                ),
            )
            if cursor.rowcount != 1:
                raise IdempotencyConflict("submission claim was lost before completion")
        return self.get(*self._key(manifest))

    def mark_submission_uncertain(
        self, manifest: Mapping[str, Any], *, operation: str, owner: str
    ) -> None:
        now = datetime.now().astimezone().isoformat(timespec="seconds")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                UPDATE publications
                SET state=?, operation_owner=NULL, operation_kind=?, lease_until=NULL,
                    updated_at=?
                WHERE channel=? AND publication_date=? AND edition=?
                  AND operation_owner=? AND operation_kind=?
                """,
                (
                    f"{operation}_submission_uncertain",
                    operation,
                    now,
                    *self._key(manifest),
                    owner,
                    operation,
                ),
            )

    def get(self, channel: str, publication_date: str, edition: str) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM publications WHERE channel=? AND publication_date=? AND edition=?",
                (channel, publication_date, edition),
            ).fetchone()
        if row is None:
            raise KeyError((channel, publication_date, edition))
        return dict(row)

    def update(self, manifest: Mapping[str, Any], **values: Any) -> dict[str, Any]:
        unknown = set(values) - self._UPDATE_FIELDS
        if unknown:
            raise ValueError(f"unsupported ledger fields: {sorted(unknown)}")
        if not values:
            return self.get(*self._key(manifest))
        values["updated_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
        assignments = ", ".join(f"{name}=?" for name in values)
        with self._connect() as connection:
            connection.execute(
                f"UPDATE publications SET {assignments} WHERE channel=? AND publication_date=? AND edition=?",
                (*values.values(), *self._key(manifest)),
            )
        return self.get(*self._key(manifest))


class PublicationService:
    """Draft, publish, or mass-send one manifest with durable backchecks."""

    def __init__(
        self,
        client: WeChatApiClient,
        ledger: PublicationLedger,
        *,
        publish_enabled: bool = False,
        approval_public_key: Any = None,
        approval_max_age_seconds: float = 24 * 60 * 60,
        submission_lease_seconds: float = 5 * 60,
        poll_attempts: int = 3,
        poll_interval: float = 2,
    ) -> None:
        self.client = client
        self.ledger = ledger
        self.publish_enabled = publish_enabled
        self.approval_public_key = approval_public_key
        self.approval_max_age = timedelta(
            seconds=max(1.0, float(approval_max_age_seconds))
        )
        self.submission_lease_seconds = max(1.0, float(submission_lease_seconds))
        self.poll_attempts = max(1, int(poll_attempts))
        self.poll_interval = max(0.0, float(poll_interval))

    @staticmethod
    def _stored_result(record: Mapping[str, Any]) -> dict[str, Any] | None:
        raw = record.get("result_json")
        if not raw:
            return None
        try:
            value = json.loads(str(raw))
        except json.JSONDecodeError:
            return None
        return value if isinstance(value, dict) else None

    def _save_result(
        self, manifest: Mapping[str, Any], result: dict[str, Any], **fields: Any
    ) -> dict[str, Any]:
        self.ledger.update(
            manifest,
            state=result["state"],
            result_json=_canonical_json(result),
            **fields,
        )
        return result

    @staticmethod
    def _base_result(manifest: Mapping[str, Any], state: str) -> dict[str, Any]:
        hashes = compute_manifest_hashes(manifest)
        return {
            "channel": manifest["channel"],
            "publication_date": manifest["publication_date"],
            "edition": manifest["edition"],
            "state": state,
            "content_sha256": hashes["content_sha256"],
            "source_sha256": hashes["source_sha256"],
            "delivery_verified": False,
        }

    def _claim_submission(
        self, manifest: Mapping[str, Any], operation: str
    ) -> tuple[str | None, dict[str, Any] | None]:
        owner = uuid.uuid4().hex
        claim = self.ledger.claim_submission(
            manifest,
            operation=operation,
            owner=owner,
            lease_seconds=self.submission_lease_seconds,
        )
        if claim["status"] == "acquired":
            return owner, None
        result = self._base_result(manifest, str(claim["status"]))
        result["operation"] = str(claim["operation"])
        if claim["status"] == "submission_uncertain":
            result["requires_manual_reconciliation"] = True
        return None, result

    def run(self, manifest: Mapping[str, Any]) -> dict[str, Any]:
        validate_manifest(manifest)
        delivery = str(manifest["delivery"])
        if delivery in {"publish", "mass"} and self.publish_enabled:
            # The approval is checked before the first WeChat network request.
            _verify_approval(
                manifest,
                self.approval_public_key,
                max_age=self.approval_max_age,
            )

        record = self.ledger.reserve(manifest, allow_review_update=True)
        stored = self._stored_result(record)
        terminal_states = {
            "drafted",
            "published",
            "delivered",
            "publish_failed",
            "delivery_failed",
        }
        if not self.publish_enabled:
            terminal_states.add("pending_approval")
        if stored and record["state"] in terminal_states:
            return stored

        draft_media_id = record.get("draft_media_id")
        if not draft_media_id:
            owner, blocked = self._claim_submission(manifest, "draft")
            if blocked is not None:
                return blocked
            try:
                draft = self.client.add_draft(manifest["article"])
            except Exception:
                self.ledger.mark_submission_uncertain(
                    manifest, operation="draft", owner=str(owner)
                )
                raise
            draft_media_id = draft["media_id"]
            record = self.ledger.complete_submission(
                manifest,
                operation="draft",
                owner=str(owner),
                state="drafted",
                draft_media_id=draft_media_id,
            )

        if delivery == "draft":
            result = self._base_result(manifest, "drafted")
            result.update({"draft_media_id": draft_media_id, "requires_approval": False})
            return self._save_result(manifest, result, draft_media_id=draft_media_id)

        if not self.publish_enabled:
            result = self._base_result(manifest, "pending_approval")
            result.update({"draft_media_id": draft_media_id, "requires_approval": True})
            return self._save_result(manifest, result, draft_media_id=draft_media_id)

        if delivery == "publish":
            return self._publish(manifest, record, str(draft_media_id))
        return self._mass_send(manifest, record, str(draft_media_id))

    def _publish(
        self, manifest: Mapping[str, Any], record: Mapping[str, Any], draft_media_id: str
    ) -> dict[str, Any]:
        publish_id = record.get("publish_id")
        if not publish_id:
            owner, blocked = self._claim_submission(manifest, "publish")
            if blocked is not None:
                return blocked
            try:
                submitted = self.client.submit_publish(draft_media_id)
            except Exception:
                self.ledger.mark_submission_uncertain(
                    manifest, operation="publish", owner=str(owner)
                )
                raise
            publish_id = submitted["publish_id"]
            self.ledger.complete_submission(
                manifest,
                operation="publish",
                owner=str(owner),
                state="publishing",
                publish_id=publish_id,
            )

        status: dict[str, Any] = {"publish_status": 1}
        for attempt in range(self.poll_attempts):
            status = self.client.get_publish_status(str(publish_id))
            if status["publish_status"] != 1:
                break
            if attempt + 1 < self.poll_attempts and self.poll_interval:
                time.sleep(self.poll_interval)

        if status["publish_status"] == 0:
            result = self._base_result(manifest, "published")
            result["delivery_verified"] = True
            result["publish_id"] = publish_id
            result["article_id"] = status.get("article_id")
            items = ((status.get("article_detail") or {}).get("item") or [])
            if items and isinstance(items[0], Mapping):
                result["article_url"] = items[0].get("article_url")
            return self._save_result(manifest, result, publish_id=publish_id)
        if status["publish_status"] == 1:
            result = self._base_result(manifest, "publishing")
            result.update({"publish_id": publish_id, "submitted_not_verified": True})
            return self._save_result(manifest, result, publish_id=publish_id)
        result = self._base_result(manifest, "publish_failed")
        result.update({"publish_id": publish_id, "platform_status": status["publish_status"]})
        return self._save_result(manifest, result, publish_id=publish_id)

    def _mass_send(
        self, manifest: Mapping[str, Any], record: Mapping[str, Any], draft_media_id: str
    ) -> dict[str, Any]:
        hashes = compute_manifest_hashes(manifest)
        edition = re.sub(r"[^a-zA-Z0-9_-]", "-", str(manifest["edition"]))[:16] or "daily"
        clientmsgid = record.get("clientmsgid") or (
            f"dt-{str(manifest['publication_date']).replace('-', '')}-{edition}-"
            f"{hashes['content_sha256'][:12]}"
        )
        msg_id = record.get("msg_id")
        if not msg_id:
            owner, blocked = self._claim_submission(manifest, "mass")
            if blocked is not None:
                return blocked
            try:
                submitted = self.client.mass_send_all(draft_media_id, str(clientmsgid))
            except Exception:
                self.ledger.mark_submission_uncertain(
                    manifest, operation="mass", owner=str(owner)
                )
                raise
            msg_id = submitted["msg_id"]
            self.ledger.complete_submission(
                manifest,
                operation="mass",
                owner=str(owner),
                state="sending",
                msg_id=str(msg_id),
                clientmsgid=str(clientmsgid),
            )

        status: dict[str, Any] = {"msg_status": "SENDING"}
        for attempt in range(self.poll_attempts):
            status = self.client.mass_get(msg_id)
            if status["msg_status"] not in {"SENDING", "SEND_JOB_SUBMITTED"}:
                break
            if attempt + 1 < self.poll_attempts and self.poll_interval:
                time.sleep(self.poll_interval)

        if status["msg_status"] == "SEND_SUCCESS":
            result = self._base_result(manifest, "delivered")
            result.update(
                {
                    "delivery_verified": True,
                    "msg_id": msg_id,
                    "clientmsgid": clientmsgid,
                }
            )
            return self._save_result(
                manifest,
                result,
                msg_id=str(msg_id),
                clientmsgid=str(clientmsgid),
            )
        if status["msg_status"] in {"SENDING", "SEND_JOB_SUBMITTED"}:
            result = self._base_result(manifest, "sending")
            result.update(
                {
                    "msg_id": msg_id,
                    "clientmsgid": clientmsgid,
                    "submitted_not_verified": True,
                }
            )
            return self._save_result(
                manifest,
                result,
                msg_id=str(msg_id),
                clientmsgid=str(clientmsgid),
            )
        result = self._base_result(manifest, "delivery_failed")
        result.update(
            {
                "msg_id": msg_id,
                "clientmsgid": clientmsgid,
                "platform_status": status["msg_status"],
            }
        )
        return self._save_result(
            manifest,
            result,
            msg_id=str(msg_id),
            clientmsgid=str(clientmsgid),
        )


__all__ = [
    "ApiError",
    "ApprovalError",
    "CredentialVaultError",
    "IdempotencyConflict",
    "ManifestError",
    "PublicationLedger",
    "PublicationService",
    "WeChatApiClient",
    "WechatCredentialVault",
    "build_approval",
    "compute_manifest_hashes",
    "validate_manifest",
]
