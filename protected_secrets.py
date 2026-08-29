"""Current-user protected persistence for local application credentials.

Only the Feishu App ID is stored as plaintext metadata.  Every value that can
authenticate or bind a webhook is serialized into one Windows DPAPI blob.  On
other operating systems callers must supply credentials through environment
variables; this module deliberately has no colocated-key fallback.  The same
boundary also protects small opaque values such as a local Fernet root key.
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import sys
import tempfile
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from wechat_runtime import (
    RuntimeSecurityError,
    ensure_private_file,
    reject_windows_reparse_chain,
)


FEISHU_SECRET_FIELDS = (
    "app_secret",
    "verify_token",
    "encrypt_key",
    "tenant_key",
)
FEISHU_CONFIG_FIELDS = ("app_id", *FEISHU_SECRET_FIELDS)
ROTATION_NOTICE = (
    "旧版明文飞书凭据已迁移到 Windows 当前用户保护存储；请轮换 App Secret、"
    "Verification Token、Encrypt Key 和 Tenant Key，旧备份可能仍保留明文。"
)

_SCHEMA = "defense-tracker.feishu-config"
_VERSION = 1
_PROTECTION = "windows-dpapi-current-user"
_MAX_CONFIG_BYTES = 256 * 1024
_PROTECTED_VALUE_SCHEMA = "defense-tracker.protected-value"
_ENVELOPE_FIELDS = {
    "schema",
    "version",
    "protection",
    "app_id",
    "protected_blob",
    "rotation_required",
}
_PROTECTED_VALUE_FIELDS = {
    "schema",
    "version",
    "protection",
    "purpose",
    "protected_blob",
}
_SAFE_MESSAGES = {
    "PROTECTION_UNAVAILABLE": (
        "Windows current-user credential protection is unavailable"
    ),
    "PROTECT_FAILED": "Local credentials could not be protected",
    "INVALID_PROTECTED_CONFIG": "Protected Feishu configuration is invalid",
    "INVALID_PROTECTED_VALUE": "Protected local value is invalid",
    "INVALID_LOCAL_CONFIG": "Local configuration is invalid",
    "PERSIST_FAILED": "Protected local configuration could not be persisted",
    "UNSAFE_CONFIG_PATH": "Protected local configuration path is unsafe",
    "CONFIG_TOO_LARGE": "Protected Feishu configuration exceeds the size limit",
    "VALUE_TOO_LARGE": "Protected local value exceeds the size limit",
}


class ProtectedSecretError(RuntimeError):
    """A stable, non-secret error raised by the protected store boundary."""

    def __init__(self, code: str) -> None:
        self.code = code if code in _SAFE_MESSAGES else "INVALID_PROTECTED_CONFIG"
        super().__init__(_SAFE_MESSAGES[self.code])


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


class WindowsCurrentUserProtector:
    """Protect bytes with Windows DPAPI under the current user identity."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise ProtectedSecretError("PROTECTION_UNAVAILABLE")

    @staticmethod
    def _blob(value: bytes) -> tuple[_DataBlob, Any]:
        buffer = ctypes.create_string_buffer(value, max(1, len(value)))
        return (
            _DataBlob(
                len(value),
                ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
            ),
            buffer,
        )

    @staticmethod
    def _call(function_name: str, value: bytes) -> bytes:
        input_blob, input_buffer = WindowsCurrentUserProtector._blob(value)
        output_blob = _DataBlob()
        try:
            function = getattr(ctypes.windll.crypt32, function_name)
            if function_name == "CryptProtectData":
                succeeded = function(
                    ctypes.byref(input_blob),
                    "DefenseTracker local credentials",
                    None,
                    None,
                    None,
                    0x1,  # CRYPTPROTECT_UI_FORBIDDEN
                    ctypes.byref(output_blob),
                )
            else:
                succeeded = function(
                    ctypes.byref(input_blob),
                    None,
                    None,
                    None,
                    None,
                    0x1,
                    ctypes.byref(output_blob),
                )
            if not succeeded:
                raise ctypes.WinError()
            return ctypes.string_at(output_blob.pbData, output_blob.cbData)
        finally:
            ctypes.memset(ctypes.addressof(input_buffer), 0, len(input_buffer))
            if output_blob.pbData:
                ctypes.windll.kernel32.LocalFree(output_blob.pbData)

    def protect(self, value: bytes) -> bytes:
        return self._call("CryptProtectData", value)

    def unprotect(self, value: bytes) -> bytes:
        return self._call("CryptUnprotectData", value)


def _assert_safe_file_path(path: Path) -> None:
    try:
        reject_windows_reparse_chain(path)
    except RuntimeSecurityError as exc:
        raise ProtectedSecretError("UNSAFE_CONFIG_PATH") from exc
    if path.is_symlink():
        raise ProtectedSecretError("UNSAFE_CONFIG_PATH")


def write_private_bytes_atomic(
    path: str | Path,
    payload: bytes,
    *,
    file_security: Any = ensure_private_file,
) -> None:
    """Commit bytes only after the temporary file passes ACL/mode checks."""

    destination = Path(path)
    _assert_safe_file_path(destination)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
        )
    except OSError as exc:
        raise ProtectedSecretError("PERSIST_FAILED") from exc

    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        file_security(temporary)
        _assert_safe_file_path(destination)
        os.replace(temporary, destination)
    except Exception as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        if isinstance(exc, ProtectedSecretError):
            raise
        raise ProtectedSecretError("PERSIST_FAILED") from exc


def write_private_json_atomic(
    path: str | Path,
    payload: Mapping[str, Any],
    *,
    file_security: Any = ensure_private_file,
) -> None:
    try:
        encoded = (
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProtectedSecretError("PERSIST_FAILED") from exc
    if len(encoded) > _MAX_CONFIG_BYTES:
        raise ProtectedSecretError("VALUE_TOO_LARGE")
    write_private_bytes_atomic(path, encoded, file_security=file_security)


def read_private_json(
    path: str | Path,
    *,
    file_security: Any = ensure_private_file,
) -> Any:
    source = Path(path)
    _assert_safe_file_path(source)
    try:
        if not source.is_file() or source.stat().st_size > _MAX_CONFIG_BYTES:
            raise ValueError("invalid local configuration file")
        file_security(source)
        _assert_safe_file_path(source)
        return json.loads(source.read_text(encoding="utf-8"))
    except ProtectedSecretError:
        raise
    except Exception as exc:
        raise ProtectedSecretError("INVALID_LOCAL_CONFIG") from exc


@dataclass(frozen=True)
class ProtectedValueLoad:
    value: bytes
    migrated: bool


class ProtectedValueStore:
    """Persist one small opaque value in a purpose-bound DPAPI envelope."""

    def __init__(
        self,
        path: str | Path,
        *,
        purpose: str,
        protector: Any | None = None,
        file_security: Any = ensure_private_file,
    ) -> None:
        if not isinstance(purpose, str) or not purpose or len(purpose) > 128:
            raise ValueError("protected value purpose is invalid")
        self.path = Path(path)
        self.purpose = purpose
        self.protector = protector
        self.file_security = file_security

    def _get_protector(self) -> Any:
        if self.protector is None:
            self.protector = WindowsCurrentUserProtector()
        return self.protector

    def _protect(self, plaintext: bytes) -> bytes:
        try:
            return self._get_protector().protect(plaintext)
        except ProtectedSecretError:
            raise
        except Exception as exc:
            raise ProtectedSecretError("PROTECT_FAILED") from exc

    def _unprotect(self, protected: bytes) -> bytes:
        try:
            return self._get_protector().unprotect(protected)
        except ProtectedSecretError:
            raise
        except Exception as exc:
            raise ProtectedSecretError("INVALID_PROTECTED_VALUE") from exc

    def save(self, value: bytes) -> None:
        if not isinstance(value, bytes) or not value:
            raise ValueError("protected value must be non-empty bytes")
        if len(value) > _MAX_CONFIG_BYTES:
            raise ProtectedSecretError("VALUE_TOO_LARGE")
        plaintext = json.dumps(
            {
                "schema": _VERSION,
                "purpose": self.purpose,
                "value": base64.b64encode(value).decode("ascii"),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        protected = self._protect(plaintext)
        envelope = {
            "schema": _PROTECTED_VALUE_SCHEMA,
            "version": _VERSION,
            "protection": _PROTECTION,
            "purpose": self.purpose,
            "protected_blob": base64.b64encode(protected).decode("ascii"),
        }
        encoded = (
            json.dumps(envelope, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
        if len(encoded) > _MAX_CONFIG_BYTES:
            raise ProtectedSecretError("VALUE_TOO_LARGE")
        write_private_bytes_atomic(
            self.path,
            encoded,
            file_security=self.file_security,
        )

    def _load_envelope(self, payload: Mapping[str, Any]) -> ProtectedValueLoad:
        if set(payload) != _PROTECTED_VALUE_FIELDS:
            raise ProtectedSecretError("INVALID_PROTECTED_VALUE")
        if (
            payload.get("schema") != _PROTECTED_VALUE_SCHEMA
            or payload.get("version") != _VERSION
            or payload.get("protection") != _PROTECTION
            or payload.get("purpose") != self.purpose
            or not isinstance(payload.get("protected_blob"), str)
        ):
            raise ProtectedSecretError("INVALID_PROTECTED_VALUE")
        try:
            protected = base64.b64decode(payload["protected_blob"], validate=True)
            if not protected:
                raise ValueError("empty protected blob")
            plaintext = json.loads(self._unprotect(protected).decode("utf-8"))
            if (
                not isinstance(plaintext, dict)
                or set(plaintext) != {"schema", "purpose", "value"}
                or plaintext.get("schema") != _VERSION
                or plaintext.get("purpose") != self.purpose
                or not isinstance(plaintext.get("value"), str)
            ):
                raise ValueError("invalid protected value payload")
            value = base64.b64decode(plaintext["value"], validate=True)
            if not value:
                raise ValueError("empty protected value")
        except ProtectedSecretError:
            raise
        except Exception as exc:
            raise ProtectedSecretError("INVALID_PROTECTED_VALUE") from exc
        return ProtectedValueLoad(value=value, migrated=False)

    def load_or_migrate_legacy(
        self,
        legacy_validator: Any | None = None,
    ) -> ProtectedValueLoad | None:
        _assert_safe_file_path(self.path)
        if not self.path.exists():
            return None
        try:
            if (
                not self.path.is_file()
                or self.path.stat().st_size > _MAX_CONFIG_BYTES
            ):
                raise ValueError("invalid protected value file")
            self.file_security(self.path)
            _assert_safe_file_path(self.path)
            raw = self.path.read_bytes()
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            legacy = raw.strip()
            try:
                accepted = bool(
                    legacy_validator is not None
                    and legacy_validator(legacy)
                )
            except Exception:
                accepted = False
            if not accepted:
                raise ProtectedSecretError("INVALID_PROTECTED_VALUE")
            self.save(legacy)
            return ProtectedValueLoad(value=legacy, migrated=True)
        except ProtectedSecretError:
            raise
        except Exception as exc:
            raise ProtectedSecretError("INVALID_PROTECTED_VALUE") from exc
        if not isinstance(payload, dict):
            raise ProtectedSecretError("INVALID_PROTECTED_VALUE")
        return self._load_envelope(payload)

    def load(self) -> ProtectedValueLoad | None:
        return self.load_or_migrate_legacy()


@dataclass(frozen=True)
class FeishuSecretLoad:
    values: dict[str, str]
    rotation_required: bool
    migrated: bool


class FeishuSecretStore:
    """Persist a versioned DPAPI envelope without plaintext Feishu secrets."""

    def __init__(
        self,
        path: str | Path,
        *,
        protector: Any | None = None,
        file_security: Any = ensure_private_file,
    ) -> None:
        self.path = Path(path)
        self.protector = protector
        self.file_security = file_security

    def _get_protector(self) -> Any:
        if self.protector is None:
            self.protector = WindowsCurrentUserProtector()
        return self.protector

    @staticmethod
    def _normalize(values: Mapping[str, Any]) -> dict[str, str]:
        if not isinstance(values, Mapping):
            raise ValueError("Feishu configuration must be a mapping")
        unknown = set(values) - set(FEISHU_CONFIG_FIELDS)
        if unknown:
            raise ValueError("unsupported Feishu configuration fields")
        normalized: dict[str, str] = {}
        for field in FEISHU_CONFIG_FIELDS:
            value = values.get(field, "")
            if value is None:
                value = ""
            if not isinstance(value, str):
                raise ValueError("Feishu configuration values must be strings")
            normalized[field] = value
        return normalized

    def _assert_safe_path(self) -> None:
        try:
            reject_windows_reparse_chain(self.path)
        except RuntimeSecurityError as exc:
            raise ProtectedSecretError("UNSAFE_CONFIG_PATH") from exc
        if self.path.is_symlink():
            raise ProtectedSecretError("UNSAFE_CONFIG_PATH")

    def _protect(self, plaintext: bytes) -> bytes:
        try:
            return self._get_protector().protect(plaintext)
        except ProtectedSecretError:
            raise
        except Exception as exc:
            raise ProtectedSecretError("PROTECT_FAILED") from exc

    def _unprotect(self, protected: bytes) -> bytes:
        try:
            return self._get_protector().unprotect(protected)
        except ProtectedSecretError:
            raise
        except Exception as exc:
            raise ProtectedSecretError("INVALID_PROTECTED_CONFIG") from exc

    def _write_atomic(self, payload: bytes) -> None:
        self._assert_safe_path()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                dir=self.path.parent,
            )
        except OSError as exc:
            raise ProtectedSecretError("PERSIST_FAILED") from exc

        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            # Validate the temporary inode's effective ACL/mode before the
            # single commit point.  The same-filesystem replace preserves it,
            # so no fallible permission operation occurs after commit.
            self.file_security(temporary)
            self._assert_safe_path()
            os.replace(temporary, self.path)
        except Exception as exc:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            if isinstance(exc, ProtectedSecretError):
                raise
            raise ProtectedSecretError("PERSIST_FAILED") from exc

    def save(
        self,
        values: Mapping[str, Any],
        *,
        rotation_required: bool = False,
    ) -> None:
        normalized = self._normalize(values)
        secret_payload = json.dumps(
            {
                "schema": _VERSION,
                "secrets": {
                    field: normalized[field] for field in FEISHU_SECRET_FIELDS
                },
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        protected = self._protect(secret_payload)
        envelope = {
            "schema": _SCHEMA,
            "version": _VERSION,
            "protection": _PROTECTION,
            "app_id": normalized["app_id"],
            "protected_blob": base64.b64encode(protected).decode("ascii"),
            "rotation_required": bool(rotation_required),
        }
        encoded = (
            json.dumps(
                envelope,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        if len(encoded) > _MAX_CONFIG_BYTES:
            raise ProtectedSecretError("CONFIG_TOO_LARGE")
        self._write_atomic(encoded)

    def _load_envelope(self, payload: Mapping[str, Any]) -> FeishuSecretLoad:
        if set(payload) != _ENVELOPE_FIELDS:
            raise ProtectedSecretError("INVALID_PROTECTED_CONFIG")
        if (
            payload.get("schema") != _SCHEMA
            or payload.get("version") != _VERSION
            or payload.get("protection") != _PROTECTION
            or not isinstance(payload.get("app_id"), str)
            or not isinstance(payload.get("protected_blob"), str)
            or not isinstance(payload.get("rotation_required"), bool)
        ):
            raise ProtectedSecretError("INVALID_PROTECTED_CONFIG")
        try:
            protected = base64.b64decode(payload["protected_blob"], validate=True)
            if not protected:
                raise ValueError("empty protected blob")
            plaintext = self._unprotect(protected)
            secret_payload = json.loads(plaintext.decode("utf-8"))
            if (
                not isinstance(secret_payload, dict)
                or secret_payload.get("schema") != _VERSION
                or set(secret_payload) != {"schema", "secrets"}
                or not isinstance(secret_payload.get("secrets"), dict)
                or set(secret_payload["secrets"]) != set(FEISHU_SECRET_FIELDS)
                or not all(
                    isinstance(secret_payload["secrets"].get(field), str)
                    for field in FEISHU_SECRET_FIELDS
                )
            ):
                raise ValueError("invalid protected payload")
        except ProtectedSecretError:
            raise
        except Exception as exc:
            raise ProtectedSecretError("INVALID_PROTECTED_CONFIG") from exc
        values = {"app_id": payload["app_id"], **secret_payload["secrets"]}
        return FeishuSecretLoad(
            values=values,
            rotation_required=payload["rotation_required"],
            migrated=False,
        )

    def _migrate_plaintext(self, payload: Mapping[str, Any]) -> FeishuSecretLoad:
        try:
            values = self._normalize(payload)
        except (TypeError, ValueError) as exc:
            raise ProtectedSecretError("INVALID_PROTECTED_CONFIG") from exc
        self.save(values, rotation_required=True)
        return FeishuSecretLoad(
            values=values,
            rotation_required=True,
            migrated=True,
        )

    def load(self) -> FeishuSecretLoad | None:
        self._assert_safe_path()
        if not self.path.exists():
            return None
        try:
            if not self.path.is_file() or self.path.stat().st_size > _MAX_CONFIG_BYTES:
                raise ValueError("invalid protected config file")
            self.file_security(self.path)
            self._assert_safe_path()
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("invalid protected config payload")
        except Exception as exc:
            raise ProtectedSecretError("INVALID_PROTECTED_CONFIG") from exc
        if payload.get("schema") == _SCHEMA:
            return self._load_envelope(payload)
        if "schema" in payload:
            raise ProtectedSecretError("INVALID_PROTECTED_CONFIG")
        return self._migrate_plaintext(payload)


__all__ = [
    "FEISHU_CONFIG_FIELDS",
    "FEISHU_SECRET_FIELDS",
    "FeishuSecretLoad",
    "FeishuSecretStore",
    "ProtectedSecretError",
    "ProtectedValueLoad",
    "ProtectedValueStore",
    "ROTATION_NOTICE",
    "WindowsCurrentUserProtector",
    "read_private_json",
    "write_private_bytes_atomic",
    "write_private_json_atomic",
]
