"""Supabase V9 client boundary: publishable config, DPAPI vault and JWT calls."""
from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import re
import secrets
import sys
import threading
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit

import requests


_PUBLISHABLE_PREFIX = "sb_publishable_"
_FORBIDDEN_CONFIG_KEYS = {
    "anon_key",
    "jwt_secret",
    "secret_key",
    "service_key",
    "service_role",
    "service_role_key",
}
_PROJECT_REF = re.compile(r"^[a-z0-9-]{6,64}$")
_AI_PROVIDER_NAMES = frozenset({"deepseek", "zhipu", "moonshot"})
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _ai_provider_name(value: object) -> str:
    provider = str(value or "").strip().lower()
    if provider not in _AI_PROVIDER_NAMES:
        raise ValueError("invalid AI provider")
    return provider


class SupabaseRequestError(RuntimeError):
    """A redacted remote failure that never embeds response bodies or tokens."""

    def __init__(self, status_code: int, operation: str):
        super().__init__(f"Supabase {operation} failed ({int(status_code)})")
        self.status_code = int(status_code)
        self.operation = operation


@dataclass(frozen=True)
class SupabaseSettings:
    url: str
    publishable_key: str
    project_ref: str
    environment: str
    redirect_ports: tuple[int, ...]
    invited_signup_enabled: bool = False

    @classmethod
    def load(cls, path: Path) -> "SupabaseSettings":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Supabase V9 config must be an object")
        if _FORBIDDEN_CONFIG_KEYS.intersection(
            str(key).lower() for key in raw
        ):
            raise ValueError("V9 config accepts a publishable key only")

        url = str(raw.get("url") or "").strip().rstrip("/")
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Supabase URL must be an HTTPS project root")
        key = str(raw.get("publishable_key") or "").strip()
        if not key.startswith(_PUBLISHABLE_PREFIX):
            raise ValueError("Supabase publishable key is required")
        project_ref = str(raw.get("project_ref") or "").strip().lower()
        if not _PROJECT_REF.fullmatch(project_ref):
            raise ValueError("invalid Supabase project_ref")
        if (
            parsed.hostname.endswith(".supabase.co")
            and parsed.hostname != f"{project_ref}.supabase.co"
        ):
            raise ValueError("Supabase URL and project_ref do not match")
        environment = str(raw.get("environment") or "staging").strip().lower()
        if environment not in {"staging", "production"}:
            raise ValueError("environment must be staging or production")
        ports = tuple(int(port) for port in raw.get("redirect_ports") or ())
        if (
            len(ports) != 5
            or len(set(ports)) != 5
            or any(port < 1024 or port > 65535 for port in ports)
        ):
            raise ValueError("exactly five unique loopback redirect ports are required")
        invited_signup_enabled = raw.get("invited_signup_enabled", False)
        if type(invited_signup_enabled) is not bool:
            raise ValueError("invited_signup_enabled must be a boolean")
        return cls(
            url,
            key,
            project_ref,
            environment,
            ports,
            invited_signup_enabled,
        )

    def public_config(self) -> dict[str, Any]:
        return {
            "configured": True,
            "url": self.url,
            "publishable_key": self.publishable_key,
            "environment": self.environment,
            "redirect_ports": list(self.redirect_ports),
            "invited_signup_enabled": self.invited_signup_enabled,
        }


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


class WindowsDpapiProtector:
    """Protect bytes for the current Windows user with DPAPI."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise RuntimeError("Windows DPAPI is unavailable on this platform")

    @staticmethod
    def _blob(value: bytes) -> tuple[_DataBlob, Any]:
        buffer = ctypes.create_string_buffer(value)
        blob = _DataBlob(
            len(value),
            ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
        )
        return blob, buffer

    @staticmethod
    def _call(function_name: str, value: bytes) -> bytes:
        input_blob, input_buffer = WindowsDpapiProtector._blob(value)
        output_blob = _DataBlob()
        crypt32 = ctypes.windll.crypt32
        function = getattr(crypt32, function_name)
        if function_name == "CryptProtectData":
            ok = function(
                ctypes.byref(input_blob),
                "DefenseTracker V9",
                None,
                None,
                None,
                0x1,
                ctypes.byref(output_blob),
            )
        else:
            ok = function(
                ctypes.byref(input_blob),
                None,
                None,
                None,
                None,
                0x1,
                ctypes.byref(output_blob),
            )
        if not ok:
            raise ctypes.WinError()
        try:
            _ = input_buffer  # Keep the backing buffer alive through the call.
            return ctypes.string_at(output_blob.pbData, output_blob.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(output_blob.pbData)

    def protect(self, value: bytes) -> bytes:
        return self._call("CryptProtectData", value)

    def unprotect(self, value: bytes) -> bytes:
        return self._call("CryptUnprotectData", value)


class SessionVault:
    """Persist only a DPAPI-protected refresh token and non-secret user id."""

    def __init__(self, vault_dir: Path, *, protector=None):
        self.path = Path(vault_dir) / "supabase-session.vault"
        self.pkce_path = Path(vault_dir) / "supabase-pkce.vault"
        self.protector = protector or WindowsDpapiProtector()

    def save_refresh_token(self, refresh_token: str, *, user_id: str) -> None:
        token = str(refresh_token or "")
        if not token:
            raise ValueError("refresh_token is required")
        if not _UUID.fullmatch(str(user_id or "")):
            raise ValueError("valid user_id is required")
        protected = self.protector.protect(token.encode("utf-8"))
        payload = {
            "schema": 1,
            "user_id": user_id,
            "protected_refresh_token": base64.b64encode(protected).decode("ascii"),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".vault.tmp")
        temporary.write_text(
            json.dumps(payload, separators=(",", ":")),
            encoding="utf-8",
        )
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        temporary.replace(self.path)

    def load_refresh_token(self) -> dict[str, str] | None:
        if not self.path.is_file():
            return None
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        protected = base64.b64decode(
            str(payload["protected_refresh_token"]),
            validate=True,
        )
        token = self.protector.unprotect(protected).decode("utf-8")
        return {"refresh_token": token, "user_id": str(payload["user_id"])}

    def clear(self) -> None:
        if not self.path.exists():
            return
        tombstone = self.path.with_suffix(".revoked")
        self.path.replace(tombstone)
        tombstone.unlink(missing_ok=True)

    def save_pkce_attempt(
        self,
        verifier: str,
        *,
        redirect_uri: str,
    ) -> None:
        verifier = str(verifier or "")
        if len(verifier) < 43 or len(verifier) > 128:
            raise ValueError("invalid PKCE verifier")
        payload = json.dumps(
            {
                "verifier": verifier,
                "redirect_uri": str(redirect_uri or ""),
                "created_at": datetime.now(timezone.utc).timestamp(),
            },
            separators=(",", ":"),
        ).encode("utf-8")
        protected = self.protector.protect(payload)
        wrapper = {
            "schema": 1,
            "protected_attempt": base64.b64encode(protected).decode("ascii"),
        }
        self.pkce_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.pkce_path.with_suffix(".vault.tmp")
        temporary.write_text(
            json.dumps(wrapper, separators=(",", ":")),
            encoding="utf-8",
        )
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        temporary.replace(self.pkce_path)

    def load_pkce_attempt(self) -> dict[str, Any] | None:
        if not self.pkce_path.is_file():
            return None
        wrapper = json.loads(self.pkce_path.read_text(encoding="utf-8"))
        protected = base64.b64decode(
            str(wrapper["protected_attempt"]),
            validate=True,
        )
        payload = json.loads(
            self.protector.unprotect(protected).decode("utf-8")
        )
        if not isinstance(payload, dict):
            raise ValueError("invalid PKCE attempt")
        return payload

    def clear_pkce_attempt(self) -> None:
        if not self.pkce_path.exists():
            return
        tombstone = self.pkce_path.with_suffix(".revoked")
        self.pkce_path.replace(tombstone)
        tombstone.unlink(missing_ok=True)


class SupabaseHttpClient:
    """Small PostgREST/Auth adapter. User identity always comes from the JWT."""

    def __init__(
        self,
        settings: SupabaseSettings,
        *,
        transport=requests,
        timeout: tuple[float, float] = (5.0, 20.0),
    ):
        self.settings = settings
        self.transport = transport
        self.timeout = timeout

    def _headers(self, access_token: str | None = None) -> dict[str, str]:
        headers = {
            "apikey": self.settings.publishable_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        operation: str,
        access_token: str | None = None,
        **kwargs,
    ) -> Any:
        response = self.transport.request(
            method,
            f"{self.settings.url}{path}",
            headers=self._headers(access_token),
            timeout=self.timeout,
            **kwargs,
        )
        if response.status_code < 200 or response.status_code >= 300:
            raise SupabaseRequestError(response.status_code, operation)
        if response.status_code == 204 or not response.text:
            return None
        return response.json()

    def validate_access_token(self, access_token: str) -> dict:
        return self._request(
            "GET",
            "/auth/v1/user",
            operation="auth validation",
            access_token=access_token,
        )

    def refresh_session(self, refresh_token: str) -> dict:
        return self._request(
            "POST",
            "/auth/v1/token?grant_type=refresh_token",
            operation="session refresh",
            json={"refresh_token": refresh_token},
        )

    def send_magic_link(
        self,
        email: str,
        redirect_uri: str,
        code_challenge: str,
    ) -> Any:
        suffix = urlencode({"redirect_to": redirect_uri})
        return self._request(
            "POST",
            f"/auth/v1/otp?{suffix}",
            operation="email PKCE start",
            json={
                "email": email,
                "create_user": self.settings.invited_signup_enabled,
                "code_challenge": code_challenge,
                "code_challenge_method": "s256",
            },
        )

    def exchange_pkce(self, auth_code: str, code_verifier: str) -> dict:
        return self._request(
            "POST",
            "/auth/v1/token?grant_type=pkce",
            operation="email PKCE exchange",
            json={
                "auth_code": auth_code,
                "code_verifier": code_verifier,
            },
        )

    def accept_pending_invitations(self, access_token: str) -> Any:
        return self.rpc(
            "accept_member_invitation",
            {},
            access_token,
        )

    def sign_out(self, access_token: str) -> Any:
        return self._request(
            "POST",
            "/auth/v1/logout?scope=global",
            operation="sign out",
            access_token=access_token,
        )

    def rpc(self, name: str, payload: dict, access_token: str) -> Any:
        if not re.fullmatch(r"[a-z][a-z0-9_]{1,63}", str(name or "")):
            raise ValueError("invalid RPC name")
        return self._request(
            "POST",
            f"/rest/v1/rpc/{name}",
            operation=f"rpc:{name}",
            access_token=access_token,
            json=payload,
        )

    def put_user_ai_credential(
        self, credential: dict, access_token: str
    ) -> Any:
        from .ai_credentials import EncryptedAiCredential

        try:
            canonical = EncryptedAiCredential.from_mapping(
                credential
            ).to_rpc_payload()
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid encrypted credential payload") from exc
        return self.rpc(
            "put_user_ai_credential",
            {"credential": canonical},
            access_token,
        )

    def list_user_ai_credentials(self, access_token: str) -> Any:
        return self.rpc("list_user_ai_credentials", {}, access_token)

    def list_user_ai_credential_devices(self, access_token: str) -> Any:
        return self.rpc(
            "list_user_ai_credential_devices", {}, access_token
        )

    def get_user_ai_credential(
        self, provider: str, access_token: str
    ) -> Any:
        return self.rpc(
            "get_user_ai_credential",
            {"provider_name": _ai_provider_name(provider)},
            access_token,
        )

    def delete_user_ai_credential(
        self, provider: str, access_token: str
    ) -> Any:
        return self.rpc(
            "delete_user_ai_credential",
            {"provider_name": _ai_provider_name(provider)},
            access_token,
        )

    def select(
        self,
        table: str,
        access_token: str,
        *,
        query: dict[str, str] | None = None,
    ) -> Any:
        if not re.fullmatch(r"[a-z][a-z0-9_]{1,63}", str(table or "")):
            raise ValueError("invalid table name")
        suffix = f"?{urlencode(query)}" if query else ""
        return self._request(
            "GET",
            f"/rest/v1/{table}{suffix}",
            operation=f"select:{table}",
            access_token=access_token,
        )

    def invoke(self, function_name: str, payload: dict, access_token: str) -> Any:
        if not re.fullmatch(r"[a-z][a-z0-9-]{1,63}", function_name):
            raise ValueError("invalid Edge Function name")
        return self._request(
            "POST",
            f"/functions/v1/{function_name}",
            operation=f"function:{function_name}",
            access_token=access_token,
            json=payload,
        )


class SupabaseSessionManager:
    """Validate browser-issued sessions, keep access tokens in memory only."""

    def __init__(
        self,
        settings: SupabaseSettings,
        vault: SessionVault,
        client: SupabaseHttpClient,
    ):
        self.settings = settings
        self.vault = vault
        self.client = client
        self._lock = threading.RLock()
        self._access_token: str | None = None
        self._expires_at = 0.0
        self._user: dict[str, Any] | None = None
        self._onboarding: dict[str, Any] | None = None

    def accept_session(
        self,
        *,
        access_token: str,
        refresh_token: str,
        expires_at: float,
    ) -> dict[str, Any]:
        user = self.client.validate_access_token(access_token)
        user_id = str(user.get("id") or "")
        if not _UUID.fullmatch(user_id):
            raise ValueError("Supabase session returned an invalid user")
        self.vault.save_refresh_token(refresh_token, user_id=user_id)
        with self._lock:
            self._access_token = access_token
            self._expires_at = float(expires_at)
            self._user = {
                "id": user_id,
                "email": str(user.get("email") or ""),
            }
        return self.status()

    def _validate_loopback_callback(self, redirect_uri: str) -> str:
        parsed = urlsplit(str(redirect_uri or ""))
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in self.settings.redirect_ports
            or parsed.path != "/api/v9/auth/callback"
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("callback must be an exact registered loopback URL")
        return redirect_uri

    def start_email_login(
        self,
        email: str,
        redirect_uri: str,
    ) -> dict[str, Any]:
        email = str(email or "").strip().lower()
        if (
            len(email) > 254
            or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)
        ):
            raise ValueError("valid invited email is required")
        callback = self._validate_loopback_callback(redirect_uri)
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).decode("ascii").rstrip("=")
        self.vault.save_pkce_attempt(
            verifier,
            redirect_uri=callback,
        )
        try:
            self.client.send_magic_link(email, callback, challenge)
        except Exception:
            self.vault.clear_pkce_attempt()
            raise
        return {"sent": True}

    def complete_email_login(self, auth_code: str) -> dict[str, Any]:
        auth_code = str(auth_code or "").strip()
        if (
            not auth_code
            or len(auth_code) > 4096
            or any(ord(character) < 33 or ord(character) > 126
                   for character in auth_code)
        ):
            raise ValueError("Supabase auth code is required")
        attempt = self.vault.load_pkce_attempt()
        if not attempt:
            raise ValueError("PKCE login was not started on this device")
        created_at = float(attempt.get("created_at") or 0)
        now = datetime.now(timezone.utc).timestamp()
        if created_at <= 0 or now - created_at > 600:
            self.vault.clear_pkce_attempt()
            raise ValueError("PKCE login attempt expired")
        session = self.client.exchange_pkce(
            auth_code,
            str(attempt.get("verifier") or ""),
        )
        access_token = str(session.get("access_token") or "")
        try:
            self.accept_session(
                access_token=access_token,
                refresh_token=str(session.get("refresh_token") or ""),
                expires_at=float(
                    session.get("expires_at")
                    or (
                        now + float(session.get("expires_in") or 0)
                    )
                ),
            )
        finally:
            # The auth code is one-time. Never retain a verifier after exchange.
            self.vault.clear_pkce_attempt()

        try:
            invitation_result = self.client.accept_pending_invitations(
                access_token
            )
            accepted_count = (
                invitation_result.get("accepted_count")
                if isinstance(invitation_result, dict)
                else None
            )
            if (
                isinstance(accepted_count, bool)
                or not isinstance(accepted_count, int)
                or accepted_count < 0
            ):
                raise ValueError("invalid invitation acceptance response")
            onboarding = {
                "status": (
                    "accepted" if accepted_count else "none_pending"
                ),
                "accepted_count": accepted_count,
            }
        except (SupabaseRequestError, requests.RequestException, ValueError):
            # The one-time login already succeeded. Preserve the valid session
            # and expose a retry state instead of consuming the code then
            # presenting the user as unauthenticated.
            onboarding = {
                "status": "retry_required",
                "accepted_count": None,
            }
        with self._lock:
            self._onboarding = onboarding
        return self.status()

    def _refresh_locked(self) -> None:
        saved = self.vault.load_refresh_token()
        if not saved:
            raise PermissionError("Supabase login is required")
        response = self.client.refresh_session(saved["refresh_token"])
        self.accept_session(
            access_token=str(response.get("access_token") or ""),
            refresh_token=str(response.get("refresh_token") or ""),
            expires_at=float(
                response.get("expires_at")
                or (
                    datetime.now(timezone.utc).timestamp()
                    + float(response.get("expires_in") or 0)
                )
            ),
        )

    def access_token(self) -> str:
        with self._lock:
            now = datetime.now(timezone.utc).timestamp()
            if not self._access_token or self._expires_at <= now + 30:
                self._refresh_locked()
            return str(self._access_token)

    def user_id(self) -> str:
        self.access_token()
        with self._lock:
            return str((self._user or {}).get("id") or "")

    def rpc(self, name: str, payload: dict) -> Any:
        return self.client.rpc(name, payload, self.access_token())

    def put_user_ai_credential(self, credential: dict) -> Any:
        return self.client.put_user_ai_credential(
            credential, self.access_token()
        )

    def list_user_ai_credentials(self) -> Any:
        return self.client.list_user_ai_credentials(self.access_token())

    def list_user_ai_credential_devices(self) -> Any:
        return self.client.list_user_ai_credential_devices(
            self.access_token()
        )

    def get_user_ai_credential(self, provider: str) -> Any:
        return self.client.get_user_ai_credential(
            provider, self.access_token()
        )

    def delete_user_ai_credential(self, provider: str) -> Any:
        return self.client.delete_user_ai_credential(
            provider, self.access_token()
        )

    def status(self) -> dict[str, Any]:
        with self._lock:
            user = dict(self._user or {})
            return {
                "configured": True,
                "authenticated": bool(self._access_token and user.get("id")),
                "user_id": user.get("id"),
                "email": user.get("email"),
                "expires_at": self._expires_at or None,
                "environment": self.settings.environment,
                "onboarding": (
                    dict(self._onboarding)
                    if self._onboarding is not None
                    else None
                ),
            }

    def clear(self) -> None:
        with self._lock:
            self._access_token = None
            self._expires_at = 0.0
            self._user = None
            self._onboarding = None
        self.vault.clear()
        self.vault.clear_pkce_attempt()

    def sign_out(self) -> None:
        try:
            token = self.access_token()
            self.client.sign_out(token)
        finally:
            self.clear()
