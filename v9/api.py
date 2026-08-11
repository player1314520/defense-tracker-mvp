"""Local desktop V9 API. Cloud-facing sync routes accept ciphertext only."""
from __future__ import annotations

import base64
import binascii
import logging
import re
import threading
import uuid
from contextlib import contextmanager
from io import BytesIO
from urllib.parse import urlsplit

from flask import Blueprint, g, jsonify, redirect, request, send_file

from .alerts import evaluate_alert_rules
from .cloud import SupabaseCoordinator, run_sync_cycle, validate_ciphertext_event
from .errors import InvalidRecordType, NotFound, PermissionDenied, VersionConflict
from .ai_credentials import (
    CredentialDeviceError,
    EncryptedAiCredential,
    InMemoryAiCredential,
)
from .ai_providers import provider_catalog, resolve_provider
from .supabase_client import SupabaseRequestError


_AUTH_CALLBACK_LOG = re.compile(
    r"(/api/v9/auth/callback)\?[^\s\"]*"
)


class _ActiveAiCredentialStore:
    """Process-local owner of clearable plaintext credential buffers."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._credential: InMemoryAiCredential | None = None
        self._identity: tuple[str, str, str] | None = None

    @staticmethod
    def _bound_identity(
        *, user_id: str, organization_id: str, device_id: str
    ) -> tuple[str, str, str]:
        identity = (
            str(user_id or ""),
            str(organization_id or ""),
            str(device_id or ""),
        )
        if not all(identity):
            raise PermissionError("active AI credential identity required")
        return identity

    def install(
        self,
        credential: InMemoryAiCredential,
        *,
        user_id: str,
        organization_id: str,
        device_id: str,
    ) -> dict:
        identity = self._bound_identity(
            user_id=user_id,
            organization_id=organization_id,
            device_id=device_id,
        )
        with self._lock:
            previous = self._credential
            if previous is not None:
                previous.clear()
            self._credential = credential
            self._identity = identity
            return {
                "provider": credential.provider,
                "model_id": credential.model_id,
                "endpoint": credential.endpoint,
                "credential_version": credential.credential_version,
                "active": True,
            }

    def status(
        self,
        *,
        user_id: str,
        organization_id: str,
        device_id: str,
    ) -> dict:
        identity = self._bound_identity(
            user_id=user_id,
            organization_id=organization_id,
            device_id=device_id,
        )
        with self._lock:
            item = self._credential
            rows = []
            if (
                item is not None
                and not item.cleared
                and self._identity == identity
            ):
                rows.append({
                    "provider": item.provider,
                    "model_id": item.model_id,
                    "endpoint": item.endpoint,
                    "credential_version": item.credential_version,
                    "active": True,
                })
        return {"credentials": rows}

    def binding(self) -> dict | None:
        """Return identity and public model metadata for trusted Python callers."""
        with self._lock:
            credential = self._credential
            identity = self._identity
            if credential is None or credential.cleared or identity is None:
                return None
            user_id, organization_id, device_id = identity
            return {
                "user_id": user_id,
                "organization_id": organization_id,
                "device_id": device_id,
                "provider": credential.provider,
                "model_id": credential.model_id,
                "credential_version": credential.credential_version,
            }

    def clear(self, provider: str | None = None) -> None:
        with self._lock:
            item = self._credential
            if item is not None and (
                provider is None or item.provider == provider
            ):
                self._credential = None
                self._identity = None
                item.clear()

    @contextmanager
    def lease(
        self,
        provider: str,
        *,
        user_id: str,
        organization_id: str,
        device_id: str,
        credential_version: int,
    ):
        provider_name = str(provider or "").strip().lower()
        if provider_name not in {
            str(item["provider"]) for item in provider_catalog()
        }:
            raise ValueError("unsupported AI provider")
        identity = self._bound_identity(
            user_id=user_id,
            organization_id=organization_id,
            device_id=device_id,
        )
        if type(credential_version) is not int or credential_version < 1:
            raise ValueError("invalid credential version")
        with self._lock:
            credential = self._credential
            if (
                credential is None
                or credential.cleared
                or credential.provider != provider_name
                or self._identity != identity
            ):
                raise PermissionError("AI credential is not active")
            if credential.credential_version != credential_version:
                self._credential = None
                self._identity = None
                credential.clear()
                raise PermissionError("AI credential version is not active")
            yield credential


_ACTIVE_AI_CREDENTIALS = _ActiveAiCredentialStore()


def active_ai_credential_status(
    *, user_id: str, organization_id: str, device_id: str
) -> dict:
    """Return metadata only; no API key bytes or text are exposed."""
    return _ACTIVE_AI_CREDENTIALS.status(
        user_id=user_id,
        organization_id=organization_id,
        device_id=device_id,
    )


def active_ai_credential_binding() -> dict | None:
    """Return the active credential binding without exposing secret material."""
    return _ACTIVE_AI_CREDENTIALS.binding()


def clear_active_ai_credentials(provider: str | None = None) -> None:
    """Best-effort zero and release one or all in-memory credentials."""
    _ACTIVE_AI_CREDENTIALS.clear(provider)


@contextmanager
def lease_active_ai_credential(
    provider: str,
    *,
    user_id: str,
    organization_id: str,
    device_id: str,
    credential_version: int,
):
    """Lease one active credential while preventing concurrent clearing."""
    with _ACTIVE_AI_CREDENTIALS.lease(
        provider,
        user_id=user_id,
        organization_id=organization_id,
        device_id=device_id,
        credential_version=credential_version,
    ) as credential:
        yield credential


def _redact_auth_callback_access_log(value: str) -> str:
    """Remove one-time auth material from Werkzeug request-line logs."""
    return _AUTH_CALLBACK_LOG.sub(
        r"\1?[REDACTED]",
        str(value),
    )


class _AuthCallbackAccessLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        redacted = _redact_auth_callback_access_log(record.getMessage())
        if redacted != record.getMessage():
            record.msg = redacted
            record.args = ()
        return True


_werkzeug_logger = logging.getLogger("werkzeug")
if not any(
    isinstance(item, _AuthCallbackAccessLogFilter)
    for item in _werkzeug_logger.filters
):
    _werkzeug_logger.addFilter(_AuthCallbackAccessLogFilter())


def create_blueprint(
    service_provider,
    auth_check=None,
    situation_provider=None,
    news_provider=None,
    agent_phase_executor=None,
    cloud_provider=None,
) -> Blueprint:
    bp = Blueprint("v9", __name__, url_prefix="/api/v9")

    def _server_port() -> int:
        try:
            port = int(str(request.environ.get("SERVER_PORT") or ""))
        except ValueError:
            return 0
        return port if 1 <= port <= 65535 else 0

    def _host_port() -> tuple[str, int]:
        parsed = urlsplit(f"//{request.host}")
        try:
            port = parsed.port
        except ValueError:
            return "", 0
        if port is None:
            port = 443 if request.scheme == "https" else 80
        return str(parsed.hostname or "").lower(), int(port)

    def _same_loopback_origin(origin: str, server_port: int) -> bool:
        try:
            parsed = urlsplit(origin)
            port = parsed.port
        except ValueError:
            return False
        if port is None:
            port = 443 if parsed.scheme == "https" else 80
        return (
            parsed.scheme == request.scheme
            and parsed.hostname in {"localhost", "127.0.0.1"}
            and port == server_port
            and not parsed.username
            and not parsed.password
            and not parsed.path
            and not parsed.query
            and not parsed.fragment
        )

    @bp.before_request
    def _guard():
        if request.remote_addr not in {"127.0.0.1", "::1", None}:
            return jsonify({"error": "V9 桌面 API 仅允许本机访问"}), 403
        server_port = _server_port()
        host, host_port = _host_port()
        if (
            host not in {"localhost", "127.0.0.1"}
            or not server_port
            or host_port != server_port
        ):
            return jsonify({"error": "V9 桌面 API Host 校验失败"}), 403
        origin = str(request.headers.get("Origin") or "").strip()
        if origin and not _same_loopback_origin(origin, server_port):
            return jsonify({"error": "V9 桌面 API Origin 校验失败"}), 403
        unsafe = request.method not in {"GET", "HEAD", "OPTIONS"}
        browser_context = bool(
            request.cookies
            or request.headers.get("Sec-Fetch-Site")
            or request.headers.get("Sec-Fetch-Mode")
        )
        if unsafe and browser_context and not origin:
            return jsonify({"error": "V9 浏览器请求缺少 Origin"}), 403
        is_pkce_callback = (
            request.method == "GET"
            and request.endpoint == f"{bp.name}.auth_callback"
        )
        if auth_check is not None and not is_pkce_callback:
            auth_response = auth_check()
            if auth_response is not None:
                return auth_response
        _require_explicit_business_context()
        return None

    @bp.errorhandler(PermissionDenied)
    def _permission(error):
        return jsonify({"error": str(error)}), 403

    @bp.errorhandler(NotFound)
    def _not_found(error):
        return jsonify({"error": str(error)}), 404

    def _bad_request(error):
        status = 409 if isinstance(error, VersionConflict) else 400
        return jsonify({"error": str(error)}), status

    for error_type in (VersionConflict, InvalidRecordType, ValueError):
        bp.register_error_handler(error_type, _bad_request)

    def _cloud():
        cloud = cloud_provider() if cloud_provider is not None else None
        if cloud is None:
            return None
        return cloud

    def _cloud_required():
        cloud = _cloud()
        if cloud is None:
            raise RuntimeError("Supabase V9 尚未配置")
        return cloud

    def _bind_cloud_device_session(cloud, context: dict) -> None:
        organization_id = _canonical_request_uuid(
            context.get("organization_id"), "organization_id"
        )
        device_id = _canonical_request_uuid(
            context.get("device_id"), "device_id"
        )
        try:
            result = cloud.rpc(
                "bind_device_session",
                {
                    "p_organization_id": organization_id,
                    "p_device_id": device_id,
                },
            )
        except SupabaseRequestError as error:
            if error.status_code == 401:
                raise PermissionError(
                    "cloud session authentication required"
                ) from None
            if error.status_code in {400, 403}:
                raise PermissionDenied(
                    "active device session binding required"
                ) from None
            raise
        if (
            not isinstance(result, dict)
            or result.get("organization_id") != organization_id
            or result.get("device_id") != device_id
            or result.get("status") != "active"
        ):
            raise PermissionDenied("active device session binding required")

    def _register_pending_cloud_device(
        cloud,
        service,
        context: dict,
        membership: dict,
    ) -> None:
        organization_id = _canonical_request_uuid(
            context.get("organization_id"), "organization_id"
        )
        user_id = _canonical_request_uuid(
            context.get("user_id"), "user_id"
        )
        device_id = _canonical_request_uuid(
            context.get("device_id"), "device_id"
        )
        if (
            user_id != cloud.user_id()
            or context.get("status") != "pending"
            or context.get("key_algorithm") != "p256"
            or context.get("device_kind") != "desktop"
            or "mvp_owner_bootstrap" in context
        ):
            raise PermissionDenied("pending cloud device identity mismatch")
        validated = service.prepare_cloud_device_registration(
            organization_id=organization_id,
            user_id=user_id,
            role=str(membership.get("role") or ""),
            membership_status=str(membership.get("status") or ""),
            key_version=int(context.get("remote_key_version") or 0),
            device_name="local desktop",
        )
        identity_fields = (
            "organization_id",
            "user_id",
            "device_id",
            "key_algorithm",
            "device_kind",
            "status",
            "remote_key_version",
            "device_public_key",
            "device_name_ciphertext",
            "device_name_nonce",
        )
        if any(
            validated.get(field) != context.get(field)
            for field in identity_fields
        ):
            raise PermissionDenied("pending cloud device identity changed")
        result = cloud.rpc(
            "register_device",
            {
                "organization_id": organization_id,
                "device_id": device_id,
                "key_algorithm": "p256",
                "device_kind": "desktop",
                "device_public_key": context["device_public_key"],
                "device_name_ciphertext": (
                    context["device_name_ciphertext"]
                ),
                "device_name_nonce": context["device_name_nonce"],
            },
        )
        if result != device_id:
            raise PermissionDenied("cloud device registration mismatch")

    def _bytea(value, field: str) -> bytes:
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        encoded = str(value or "")
        if (
            not encoded.startswith("\\x")
            or len(encoded) < 4
            or len(encoded) % 2
        ):
            raise ValueError(f"{field} 编码无效")
        try:
            return bytes.fromhex(encoded[2:])
        except ValueError:
            raise ValueError(f"{field} 编码无效") from None

    def _canonical_request_uuid(value, field: str) -> str:
        raw = str(value or "")
        try:
            canonical = str(uuid.UUID(raw))
        except (ValueError, AttributeError, TypeError):
            raise ValueError(f"{field} 必须是 UUID") from None
        if canonical != raw:
            raise ValueError(f"{field} 必须是规范 UUID")
        return canonical

    def _require_explicit_business_context() -> None:
        path = request.path
        if (
            path.startswith("/api/v9/auth/")
            or path in {
                "/api/v9/business-context/personal",
                "/api/v9/organizations",
                "/api/v9/organizations/bootstrap",
                "/api/v9/organizations/bootstrap/acknowledge",
                "/api/v9/situation",
                "/api/v9/pairing-sessions/claim",
            }
        ):
            return

        raw_mode = str(
            request.headers.get("X-V9-Context-Mode") or ""
        ).strip()
        if not raw_mode:
            raise ValueError("X-V9-Context-Mode 必填")
        mode = raw_mode.lower()
        if mode not in {"personal", "cloud"}:
            raise ValueError(
                "X-V9-Context-Mode 必须是 personal 或 cloud"
            )
        endpoint = str(request.endpoint or "").rsplit(".", 1)[-1]
        cloud_only = {
            "cloud_devices",
            "advance_cloud_device",
            "approve_cloud_device",
            "invite_cloud_member",
            "list_cloud_member_invitations",
            "cancel_cloud_member_invitation",
            "run_cloud_sync",
            "list_ai_credentials",
            "save_ai_credential",
            "activate_ai_credential",
            "rewrap_ai_credential",
            "delete_ai_credential",
        }
        personal_only = {
            "bootstrap_cloud_snapshot",
            "complete_cloud_snapshot",
            "add_member",
            "revoke_member",
            "pair_device",
            "create_pairing_session",
            "recover_device",
            "revoke_device",
        }
        if endpoint in cloud_only and mode != "cloud":
            raise ValueError("X-V9-Context-Mode 必须为 cloud")
        if endpoint in personal_only and mode != "personal":
            raise ValueError("X-V9-Context-Mode 必须为 personal")
        organization_id = _canonical_request_uuid(
            request.headers.get("X-V9-Organization-ID"),
            "X-V9-Organization-ID",
        )
        g.v9_asserted_context_mode = mode
        g.v9_asserted_organization_id = organization_id

        candidates = []
        view_args = request.view_args or {}
        if view_args.get("org_id"):
            candidates.append(("organization_id", view_args["org_id"]))
        if request.args.get("organization_id"):
            candidates.append(
                ("organization_id", request.args.get("organization_id"))
            )
        data = request.get_json(silent=True) if request.is_json else None
        if isinstance(data, dict):
            if data.get("organization_id"):
                candidates.append(
                    ("organization_id", data.get("organization_id"))
                )
            for field in ("event", "resolution_event"):
                nested = data.get(field)
                if isinstance(nested, dict) and nested.get("organization_id"):
                    candidates.append(
                        ("organization_id", nested.get("organization_id"))
                    )
        for field, candidate in candidates:
            asserted = _canonical_request_uuid(candidate, field)
            if asserted != organization_id:
                raise PermissionDenied(
                    "business context organization mismatch"
                )

    def _self_cloud_membership(cloud, organization_id: str) -> dict:
        user_id = cloud.user_id()
        rows = cloud.client.select(
            "memberships",
            cloud.access_token(),
            query={
                "select": "organization_id,user_id,role,status",
                "organization_id": f"eq.{organization_id}",
                "user_id": f"eq.{user_id}",
                "status": "in.(active,invited)",
                "limit": "1",
            },
        )
        if not rows:
            raise PermissionDenied("active or invited membership required")
        membership = dict(rows[0])
        if (
            membership.get("organization_id") != organization_id
            or membership.get("user_id") != user_id
            or membership.get("status") not in {"active", "invited"}
        ):
            raise PermissionDenied("cloud membership identity mismatch")
        return membership

    def _bound_cloud_organization(cloud, organization_id: str) -> dict:
        rows = cloud.client.select(
            "organizations",
            cloud.access_token(),
            query={
                "select": "id,key_version",
                "id": f"eq.{organization_id}",
                "limit": "1",
            },
        )
        if not isinstance(rows, list) or len(rows) != 1:
            raise PermissionDenied("bound cloud organization required")
        organization = dict(rows[0])
        key_version = organization.get("key_version")
        if (
            organization.get("id") != organization_id
            or isinstance(key_version, bool)
            or not isinstance(key_version, int)
            or key_version < 1
        ):
            raise PermissionDenied("cloud organization metadata mismatch")
        return organization

    def _remote_cloud_devices(cloud, organization_id: str) -> list[dict]:
        rows = cloud.client.select(
            "devices",
            cloud.access_token(),
            query={
                "select": (
                    "id,organization_id,user_id,key_algorithm,device_kind,"
                    "public_key,status"
                ),
                "organization_id": f"eq.{organization_id}",
                "order": "created_at.asc",
            },
        )
        normalized = []
        for row in rows:
            device = dict(row)
            device["public_key"] = _bytea(
                device.get("public_key"), "设备公钥"
            )
            normalized.append(device)
        return normalized

    def _remote_cloud_device_identity(
        cloud,
        organization_id: str,
        user_id: str,
        device_id: str,
    ) -> list[dict]:
        rows = cloud.client.select(
            "devices",
            cloud.access_token(),
            query={
                "select": (
                    "id,organization_id,user_id,key_algorithm,device_kind,"
                    "public_key,status"
                ),
                "organization_id": f"eq.{organization_id}",
                "user_id": f"eq.{user_id}",
                "id": f"eq.{device_id}",
                "status": "eq.active",
                "limit": "2",
            },
        )
        if not isinstance(rows, list) or len(rows) > 1:
            raise PermissionDenied("active remote device required")
        normalized = []
        for row in rows:
            if not isinstance(row, dict):
                raise PermissionDenied("active remote device required")
            device = dict(row)
            device["public_key"] = _bytea(
                device.get("public_key"),
                "设备公钥",
            )
            normalized.append(device)
        return normalized

    def _remote_cloud_key_envelope(
        cloud,
        organization_id: str,
        device_id: str,
        key_version: int,
    ) -> dict | None:
        rows = cloud.client.select(
            "key_envelopes",
            cloud.access_token(),
            query={
                "select": (
                    "organization_id,device_id,key_version,key_algorithm,"
                    "ephemeral_public_key,nonce,ciphertext"
                ),
                "organization_id": f"eq.{organization_id}",
                "device_id": f"eq.{device_id}",
                "key_version": f"eq.{key_version}",
                "order": "key_version.desc",
                "limit": "1",
            },
        )
        if not isinstance(rows, list) or len(rows) > 1:
            raise PermissionDenied("organization key envelope is ambiguous")
        if not rows:
            return None
        remote = dict(rows[0])
        ephemeral_public_key = _bytea(
            remote.get("ephemeral_public_key"),
            "envelope ephemeral public key",
        )
        nonce = _bytea(remote.get("nonce"), "envelope nonce")
        ciphertext = _bytea(remote.get("ciphertext"), "envelope ciphertext")
        if (
            remote.get("organization_id") != organization_id
            or remote.get("device_id") != device_id
            or type(remote.get("key_version")) is not int
            or remote.get("key_version") != key_version
            or remote.get("key_algorithm") != "p256"
            or len(ephemeral_public_key) != 65
            or ephemeral_public_key[0] != 4
            or len(nonce) != 12
            or len(ciphertext) != 48
        ):
            raise PermissionDenied(
                "organization key envelope binding mismatch"
            )
        return {
            "organization_id": organization_id,
            "device_id": device_id,
            "key_version": key_version,
            "key_algorithm": "p256",
            "ephemeral_public_key": base64.urlsafe_b64encode(
                ephemeral_public_key
            ).decode("ascii").rstrip("="),
            "nonce": base64.urlsafe_b64encode(nonce).decode(
                "ascii"
            ).rstrip("="),
            "ciphertext": base64.urlsafe_b64encode(ciphertext).decode(
                "ascii"
            ).rstrip("="),
        }

    def _sync_cloud_devices(cloud, organization_id: str) -> list[dict]:
        rows = cloud.rpc(
            "list_sync_devices",
            {"p_organization_id": organization_id},
        ) or []
        if not isinstance(rows, list) or len(rows) > 10000:
            raise ValueError("同步设备目录响应无效")
        normalized = []
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("同步设备目录响应无效")
            org_id = _canonical_request_uuid(
                row.get("org_id"), "organization_id"
            )
            device_id = _canonical_request_uuid(
                row.get("device_id"), "device_id"
            )
            algorithm = str(row.get("key_algorithm") or "")
            encoded_key = str(row.get("public_key") or "")
            if (
                org_id != organization_id
                or algorithm not in {"x25519", "p256"}
                or not re.fullmatch(r"[A-Za-z0-9_-]+", encoded_key)
            ):
                raise PermissionDenied("invalid sync device metadata")
            try:
                public_key = base64.urlsafe_b64decode(
                    encoded_key + ("=" * (-len(encoded_key) % 4))
                )
            except (ValueError, binascii.Error):
                raise ValueError("同步设备公钥编码无效") from None
            if len(public_key) != (32 if algorithm == "x25519" else 65):
                raise ValueError("同步设备公钥长度无效")
            normalized.append({
                "org_id": org_id,
                "device_id": device_id,
                "key_algorithm": algorithm,
                "device_kind": None,
                "public_key": public_key,
                "status": "active",
            })
        return normalized

    def _personal_context(
        organization_id: str = "",
        device_id: str = "",
        *,
        create: bool = False,
    ) -> dict:
        service = service_provider()
        context = (
            service.get_or_create_personal_context()
            if create
            else service.get_personal_context()
        )
        if context is None:
            raise PermissionDenied("local personal context required")
        pending_check = getattr(
            service, "personal_recovery_pending", None
        )
        if callable(pending_check) and pending_check():
            raise PermissionDenied(
                "personal recovery acknowledgement required"
            )
        if organization_id and organization_id != context["organization_id"]:
            raise PermissionDenied("local personal organization required")
        if device_id and device_id != context["device_id"]:
            raise PermissionDenied("local personal device required")
        return context

    def _business_context(
        organization_id: str = "",
        device_id: str = "",
        *,
        create: bool = False,
        optional: bool = False,
    ) -> dict | None:
        mode = str(getattr(g, "v9_asserted_context_mode", "") or "")
        header_org = str(
            getattr(g, "v9_asserted_organization_id", "") or ""
        )
        if not mode or not header_org:
            _require_explicit_business_context()
            mode = str(g.v9_asserted_context_mode)
            header_org = str(g.v9_asserted_organization_id)
        asserted_org = str(organization_id or "").strip()
        if asserted_org and header_org != asserted_org:
            raise PermissionDenied("business context organization mismatch")
        requested_org = header_org

        if mode == "personal":
            service = service_provider()
            context = (
                service.get_or_create_personal_context()
                if create
                else service.get_personal_context()
            )
            if context is None:
                if not optional:
                    raise PermissionDenied(
                        "local personal context required"
                    )
                g.v9_resolved_context_mode = "personal"
                return None
            pending_check = getattr(
                service, "personal_recovery_pending", None
            )
            if callable(pending_check) and pending_check():
                raise PermissionDenied(
                    "personal recovery acknowledgement required"
                )
            if requested_org != context["organization_id"]:
                raise PermissionDenied(
                    "local personal organization required"
                )
            if device_id and device_id != context["device_id"]:
                raise PermissionDenied("local personal device required")
            g.v9_resolved_context_mode = "personal"
            g.v9_resolved_organization_id = context["organization_id"]
            return context

        cloud = _cloud_required()
        cloud.access_token()
        cloud_user_id = cloud.user_id()
        membership = _self_cloud_membership(cloud, requested_org)
        if (
            membership.get("organization_id") != requested_org
            or membership.get("user_id") != cloud_user_id
            or membership.get("status") != "active"
        ):
            raise PermissionDenied("active cloud membership required")

        service = service_provider()
        context = service.resolve_cloud_context(
            requested_org,
            cloud_user_id,
        )
        _bind_cloud_device_session(cloud, context)
        remote_organization = _bound_cloud_organization(
            cloud, requested_org
        )
        remote_key_version = remote_organization.get("key_version")
        local_key_version = context.get("key_version")
        if (
            isinstance(remote_key_version, bool)
            or not isinstance(remote_key_version, int)
            or remote_key_version < 1
            or isinstance(local_key_version, bool)
            or not isinstance(local_key_version, int)
            or local_key_version < 1
            or remote_key_version != local_key_version
        ):
            raise PermissionDenied(
                "cloud key version mismatch; "
                "use /api/v9/devices/self first"
            )
        context_device_id = _canonical_request_uuid(
            context.get("device_id"),
            "device_id",
        )
        encoded_public_key = str(
            context.get("device_public_key") or ""
        )
        if (
            context.get("organization_id") != requested_org
            or context.get("user_id") != cloud_user_id
            or context.get("key_algorithm") != "p256"
            or context.get("device_kind") != "desktop"
            or context.get("status") != "active"
            or not re.fullmatch(
                r"[A-Za-z0-9_-]+",
                encoded_public_key,
            )
        ):
            raise PermissionDenied("active cloud device context required")
        try:
            expected_public_key = base64.urlsafe_b64decode(
                encoded_public_key
                + ("=" * (-len(encoded_public_key) % 4))
            )
        except (ValueError, binascii.Error):
            raise PermissionDenied(
                "active cloud device context required"
            ) from None
        if len(expected_public_key) != 65:
            raise PermissionDenied("active cloud device context required")

        remote_matches = [
            remote
            for remote in _remote_cloud_device_identity(
                cloud,
                requested_org,
                cloud_user_id,
                context_device_id,
            )
            if (
                remote.get("id") == context_device_id
                and remote.get("organization_id") == requested_org
                and remote.get("user_id") == cloud_user_id
                and remote.get("key_algorithm")
                == context.get("key_algorithm")
                and remote.get("device_kind") == "desktop"
                and remote.get("public_key") == expected_public_key
                and remote.get("status") == "active"
            )
        ]
        if len(remote_matches) != 1:
            raise PermissionDenied("active remote device required")
        if device_id and device_id != context["device_id"]:
            raise PermissionDenied("cloud device context mismatch")

        service.refresh_cloud_membership(
            context,
            cloud_user_id=cloud_user_id,
            role=str(membership.get("role") or ""),
        )
        g.v9_resolved_context_mode = "cloud"
        g.v9_resolved_organization_id = requested_org
        return context

    @bp.after_request
    def _business_context_response_headers(response):
        if request.path.startswith((
            "/api/v9/auth/",
            "/api/v9/ai/credentials",
            "/api/v9/business-context/",
            "/api/v9/organizations",
            "/api/v9/devices",
            "/api/v9/pairing-sessions",
            "/api/v9/members",
        )):
            response.headers["Cache-Control"] = "no-store, private"
            response.headers["Pragma"] = "no-cache"
        mode = getattr(g, "v9_resolved_context_mode", "")
        if mode and 200 <= response.status_code < 400:
            response.headers["X-V9-Resolved-Context-Mode"] = mode
            response.vary.add("X-V9-Context-Mode")
            response.vary.add("X-V9-Organization-ID")
            organization_id = getattr(
                g,
                "v9_resolved_organization_id",
                "",
            )
            if organization_id:
                response.headers[
                    "X-V9-Resolved-Organization-ID"
                ] = organization_id
        return response

    @bp.errorhandler(RuntimeError)
    def _runtime_error(error):
        return jsonify({"error": str(error)}), 503

    @bp.errorhandler(PermissionError)
    def _cloud_auth_error(error):
        return jsonify({"error": str(error)}), 401

    @bp.get("/business-context/personal")
    def personal_business_context():
        service = service_provider()
        context = service.get_personal_context()
        if context is None:
            return jsonify({
                "error": "local personal context is not initialized",
            }), 409
        pending_check = getattr(
            service, "personal_recovery_pending", None
        )
        if callable(pending_check) and pending_check():
            return jsonify({
                "error": "personal recovery acknowledgement required",
                "recovery_pending": True,
            }), 409
        return jsonify({
            "mode": "personal",
            "organization_id": context["organization_id"],
        })

    @bp.get("/auth/start")
    def auth_start():
        cloud = _cloud()
        if cloud is None:
            return jsonify({"configured": False})
        return jsonify(cloud.settings.public_config())

    @bp.post("/auth/start")
    def start_email_auth():
        data = request.get_json(silent=True) or {}
        port = _server_port()
        callback = (
            f"http://127.0.0.1:{port}/api/v9/auth/callback"
        )
        result = _cloud_required().start_email_login(
            str(data.get("email") or ""),
            callback,
        )
        return jsonify(result), 202

    @bp.get("/auth/callback")
    def auth_callback():
        if request.args.get("error"):
            return jsonify({"error": "Supabase 邮箱验证失败"}), 400
        if (
            set(request.args.keys()) != {"code"}
            or len(request.args.getlist("code")) != 1
        ):
            return jsonify({"error": "Supabase PKCE 回调无效"}), 400
        code = str(request.args.get("code") or "").strip()
        if (
            not code
            or len(code) > 4096
            or any(ord(character) < 33 or ord(character) > 126
                   for character in code)
        ):
            return jsonify({"error": "Supabase PKCE 回调无效"}), 400
        clear_active_ai_credentials()
        _cloud_required().complete_email_login(code)
        return redirect("/?v9-auth=complete")

    @bp.get("/auth/session")
    def auth_session():
        cloud = _cloud()
        if cloud is None:
            return jsonify({"configured": False, "authenticated": False})
        return jsonify(cloud.status())

    @bp.get("/auth/realtime-token")
    def realtime_access_token():
        cloud = _cloud_required()
        token = cloud.access_token()
        status = cloud.status()
        return jsonify({
            "access_token": token,
            "expires_at": status.get("expires_at"),
        })

    @bp.delete("/auth/session")
    def clear_auth_session():
        try:
            _cloud_required().sign_out()
        finally:
            clear_active_ai_credentials()
        return jsonify({"authenticated": False})

    def _ai_provider_name(value: object) -> str:
        provider = str(value or "").strip().lower()
        if provider not in {
            str(item["provider"]) for item in provider_catalog()
        }:
            raise ValueError("unsupported AI provider")
        return provider

    def _ai_organization_id(data: dict | None = None) -> str:
        raw = (
            (data or {}).get("organization_id")
            if data is not None
            else request.args.get("organization_id")
        )
        return _canonical_request_uuid(raw, "organization_id")

    def _ai_devices(cloud) -> list[dict]:
        rows = cloud.list_user_ai_credential_devices()
        if not isinstance(rows, list) or not rows or len(rows) > 32:
            raise PermissionDenied(
                "active desktop P-256 device directory required"
            )
        if any(not isinstance(row, dict) for row in rows):
            raise ValueError("invalid AI credential device directory")
        return [dict(row) for row in rows]

    @bp.get("/ai/credentials")
    def list_ai_credentials():
        organization_id = _ai_organization_id()
        context = _business_context(organization_id)
        cloud = _cloud_required()
        cloud_user_id = cloud.user_id()
        if cloud_user_id != context.get("user_id"):
            clear_active_ai_credentials()
            raise PermissionDenied("cloud session identity changed")
        rows = cloud.list_user_ai_credentials()
        if not isinstance(rows, list) or len(rows) > 3:
            raise ValueError("invalid AI credential metadata response")
        allowed = {
            "provider",
            "model_id",
            "credential_version",
            "updated_at",
            "device_count",
        }
        metadata = []
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("invalid AI credential metadata response")
            provider = _ai_provider_name(row.get("provider"))
            model_id = str(row.get("model_id") or "")
            resolve_provider(provider, model_id)
            metadata.append({
                key: row.get(key)
                for key in allowed
            })
        return jsonify({
            "credentials": metadata,
            "active": active_ai_credential_status(
                user_id=cloud_user_id,
                organization_id=context["organization_id"],
                device_id=context["device_id"],
            )["credentials"],
        })

    @bp.put("/ai/credentials/<provider>")
    def save_ai_credential(provider):
        data = request.get_json(silent=True) or {}
        if set(data) != {
            "organization_id",
            "model_id",
            "credential_version",
            "api_key",
        }:
            raise ValueError("invalid AI credential request")
        organization_id = _ai_organization_id(data)
        context = _business_context(organization_id)
        cloud = _cloud_required()
        cloud_user_id = cloud.user_id()
        if cloud_user_id != context.get("user_id"):
            clear_active_ai_credentials()
            raise PermissionDenied("cloud session identity changed")
        provider = _ai_provider_name(provider)
        model_id = str(data.get("model_id") or "")
        resolve_provider(provider, model_id)
        version = data.get("credential_version")
        if isinstance(version, bool) or not isinstance(version, int):
            raise ValueError("invalid credential version")
        encrypted = service_provider().encrypt_cloud_ai_credential(
            context,
            cloud_user_id=cloud_user_id,
            api_key=data.get("api_key"),
            provider=provider,
            model_id=model_id,
            credential_version=version,
            devices=_ai_devices(cloud),
        )
        result = cloud.put_user_ai_credential(encrypted.to_rpc_payload())
        if not isinstance(result, dict):
            raise ValueError("invalid AI credential storage response")
        clear_active_ai_credentials(provider)
        return jsonify({
            "provider": encrypted.provider,
            "model_id": encrypted.model_id,
            "credential_version": encrypted.credential_version,
            "device_count": len(encrypted.device_envelopes),
            "stored": True,
        })

    @bp.post("/ai/credentials/<provider>/activate")
    def activate_ai_credential(provider):
        data = request.get_json(silent=True) or {}
        if set(data) != {"organization_id"}:
            raise ValueError("invalid AI credential activation request")
        organization_id = _ai_organization_id(data)
        context = _business_context(organization_id)
        cloud = _cloud_required()
        cloud_user_id = cloud.user_id()
        if cloud_user_id != context.get("user_id"):
            clear_active_ai_credentials()
            raise PermissionDenied("cloud session identity changed")
        provider = _ai_provider_name(provider)
        encrypted_payload = cloud.get_user_ai_credential(provider)
        if encrypted_payload is None:
            raise NotFound("AI credential")
        encrypted = EncryptedAiCredential.from_mapping(encrypted_payload)
        try:
            credential = service_provider().open_cloud_ai_credential(
                context,
                encrypted,
                cloud_user_id=cloud_user_id,
            )
        except CredentialDeviceError:
            return jsonify({
                "status": "reentry_required",
                "reason": "trusted_device_unavailable",
            }), 409
        try:
            status = _ACTIVE_AI_CREDENTIALS.install(
                credential,
                user_id=cloud_user_id,
                organization_id=context["organization_id"],
                device_id=context["device_id"],
            )
        except Exception:
            credential.clear()
            raise
        return jsonify(status)

    @bp.post("/ai/credentials/<provider>/rewrap")
    def rewrap_ai_credential(provider):
        data = request.get_json(silent=True) or {}
        if set(data) != {"organization_id", "target_device_id"}:
            raise ValueError("invalid AI credential rewrap request")
        organization_id = _ai_organization_id(data)
        context = _business_context(organization_id)
        cloud = _cloud_required()
        provider = _ai_provider_name(provider)
        target_device_id = _canonical_request_uuid(
            data.get("target_device_id"), "target_device_id"
        )
        devices = _ai_devices(cloud)
        targets = [
            row for row in devices
            if str(row.get("id") or row.get("device_id") or "")
            == target_device_id
        ]
        if len(targets) != 1:
            raise PermissionDenied("eligible target desktop device required")
        encrypted_payload = cloud.get_user_ai_credential(provider)
        if encrypted_payload is None:
            raise NotFound("AI credential")
        result = service_provider().rewrap_cloud_ai_credential(
            context,
            EncryptedAiCredential.from_mapping(encrypted_payload),
            cloud_user_id=cloud.user_id(),
            target_device=targets[0],
        )
        if result.status != "rewrapped" or result.credential is None:
            return jsonify({
                "status": "reentry_required",
                "reason": "trusted_device_unavailable",
            }), 409
        stored = cloud.put_user_ai_credential(
            result.credential.to_rpc_payload()
        )
        if not isinstance(stored, dict):
            raise ValueError("invalid AI credential storage response")
        return jsonify({
            "status": "rewrapped",
            "provider": result.credential.provider,
            "credential_version": result.credential.credential_version,
            "target_device_id": target_device_id,
        })

    @bp.delete("/ai/credentials/<provider>")
    def delete_ai_credential(provider):
        data = request.get_json(silent=True) or {}
        if set(data) != {"organization_id"}:
            raise ValueError("invalid AI credential deletion request")
        organization_id = _ai_organization_id(data)
        _business_context(organization_id)
        provider = _ai_provider_name(provider)
        result = _cloud_required().delete_user_ai_credential(provider)
        clear_active_ai_credentials(provider)
        return jsonify({
            "provider": provider,
            "deleted": bool(
                result.get("deleted")
                if isinstance(result, dict)
                else result
            ),
        })

    @bp.get("/organizations")
    def cloud_organizations():
        cloud = _cloud_required()
        rows = cloud.client.select(
            "memberships",
            cloud.access_token(),
            query={
                "select": "organization_id,user_id,role,status",
                "user_id": f"eq.{cloud.user_id()}",
                "status": "in.(active,invited)",
                "order": "organization_id.asc",
            },
        )
        if not isinstance(rows, list) or len(rows) > 8:
            raise ValueError("invalid organization membership response")
        organizations = []
        service = service_provider()
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("invalid organization membership response")
            organization_id = _canonical_request_uuid(
                row.get("organization_id"), "organization_id"
            )
            if row.get("user_id") != cloud.user_id():
                raise PermissionDenied("cloud membership identity mismatch")
            context = service.get_cloud_device_context(organization_id)
            metadata = None
            if context is not None and context.get("status") == "active":
                _bind_cloud_device_session(cloud, context)
                metadata = _bound_cloud_organization(
                    cloud, organization_id
                )
            organizations.append({
                "organization_id": organization_id,
                "role": row.get("role"),
                "status": row.get("status"),
                "device_status": (
                    context.get("status") if context is not None else "missing"
                ),
                "organization": metadata,
            })
        return jsonify({"organizations": organizations})

    @bp.post("/organizations")
    def bootstrap_cloud_organization():
        return jsonify({
            "status": "operator_provisioning_required",
            "manifest_command": "scripts/export_mvp_owner_manifest.py",
        }), 409

    @bp.get("/devices")
    def cloud_devices():
        organization_id = str(
            request.args.get("organization_id") or ""
        ).strip()
        if not organization_id:
            return jsonify({"error": "organization_id 必填"}), 400
        cloud = _cloud_required()
        rows = cloud.client.select(
            "devices",
            cloud.access_token(),
            query={
                "select": (
                    "id,organization_id,user_id,key_algorithm,device_kind,"
                    "public_key,status,last_seen_at,revoked_at,created_at"
                ),
                "organization_id": f"eq.{organization_id}",
                "order": "created_at.asc",
            },
        )
        return jsonify({"devices": rows})

    @bp.post("/devices/self")
    def advance_cloud_device():
        data = request.get_json(silent=True) or {}
        organization_id = str(data.get("organization_id") or "").strip()
        if not organization_id:
            return jsonify({"error": "organization_id 必填"}), 400
        cloud = _cloud_required()
        invitation_result = cloud.rpc("accept_member_invitation", {})
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
            raise ValueError("邀请接受响应无效")
        membership = _self_cloud_membership(cloud, organization_id)
        service = service_provider()
        context = service.get_cloud_device_context(organization_id)
        if (
            context is not None
            and context.get("user_id") != cloud.user_id()
        ):
            raise PermissionDenied("cloud device context identity mismatch")
        created = context is None
        if context is None:
            context = service.prepare_cloud_device_registration(
                organization_id=organization_id,
                user_id=cloud.user_id(),
                role=str(membership["role"]),
                membership_status=str(membership["status"]),
                key_version=1,
                device_name="本机桌面",
            )
        if created:
            _register_pending_cloud_device(
                cloud,
                service,
                context,
                membership,
            )
            return jsonify({
                "organization_id": organization_id,
                "device_id": context["device_id"],
                "status": "pending",
            }), 202
        try:
            _bind_cloud_device_session(cloud, context)
        except PermissionDenied:
            if context.get("status") == "active":
                raise PermissionDenied(
                    "active device session binding required"
                ) from None
            if "mvp_owner_bootstrap" not in context:
                _register_pending_cloud_device(
                    cloud,
                    service,
                    context,
                    membership,
                )
            return jsonify({
                "organization_id": organization_id,
                "device_id": context["device_id"],
                "status": "pending",
            }), 202
        key_version = int(
            _bound_cloud_organization(
                cloud, organization_id
            )["key_version"]
        )
        cloud_user_id = cloud.user_id()
        matches = _remote_cloud_device_identity(
            cloud,
            organization_id,
            cloud_user_id,
            str(context["device_id"]),
        )
        if len(matches) != 1:
            raise PermissionDenied("active remote device required")
        remote_device = matches[0]
        expected_public_key = base64.urlsafe_b64decode(
            str(context.get("device_public_key") or "")
            + ("=" * (-len(str(context.get("device_public_key") or "")) % 4))
        )
        if (
            len(matches) != 1
            or remote_device.get("organization_id") != organization_id
            or remote_device.get("user_id") != cloud_user_id
            or remote_device.get("key_algorithm") != "p256"
            or remote_device.get("device_kind") != "desktop"
            or remote_device.get("public_key") != expected_public_key
            or remote_device.get("status") != "active"
        ):
            raise PermissionDenied("remote cloud device identity mismatch")
        has_bootstrap_marker = (
            context.get("status") == "pending"
            and "mvp_owner_bootstrap" in context
        )
        bootstrap_binding_valid = (
            has_bootstrap_marker
            and service.can_activate_bootstrapped_cloud_context(
                context,
                authenticated_session=cloud,
                membership=membership,
                expected_key_version=key_version,
            )
        )
        if has_bootstrap_marker and not bootstrap_binding_valid:
            raise PermissionDenied("MVP Owner bootstrap binding mismatch")
        if bootstrap_binding_valid:
            bootstrap_envelope = _remote_cloud_key_envelope(
                cloud,
                organization_id,
                str(context["device_id"]),
                key_version,
            )
            if bootstrap_envelope is None:
                bootstrap_envelope = (
                    service.build_bootstrapped_cloud_key_envelope(
                        context,
                        remote_device=remote_device,
                        expected_key_version=key_version,
                        membership=membership,
                        authenticated_session=cloud,
                    )
                )
                ready = cloud.rpc(
                    "put_mvp_first_owner_key_envelope",
                    {
                        "p_key_version": key_version,
                        "p_ephemeral_public_key": bootstrap_envelope[
                            "ephemeral_public_key"
                        ],
                        "p_envelope_nonce": bootstrap_envelope["nonce"],
                        "p_envelope_ciphertext": bootstrap_envelope[
                            "ciphertext"
                        ],
                    },
                )
                if (
                    not isinstance(ready, dict)
                    or set(ready) != {
                        "status",
                        "organization_id",
                        "device_id",
                        "key_version",
                    }
                    or ready.get("status") != "ready"
                    or ready.get("organization_id") != organization_id
                    or ready.get("device_id") != context["device_id"]
                    or type(ready.get("key_version")) is not int
                    or ready.get("key_version") != key_version
                ):
                    raise PermissionDenied(
                        "MVP Owner key envelope response mismatch"
                    )
            active = service.activate_bootstrapped_cloud_context(
                context,
                remote_device=remote_device,
                envelope=bootstrap_envelope,
                expected_key_version=key_version,
                membership=membership,
                authenticated_session=cloud,
            )
            _bind_cloud_device_session(cloud, active)
            return jsonify({
                "organization_id": organization_id,
                "device_id": active["device_id"],
                "status": "active",
                "key_version": active["key_version"],
            })
        if context.get("status") == "active":
            if str(membership.get("status") or "") != "active":
                raise PermissionDenied("active cloud membership required")
            service.refresh_cloud_membership(
                context,
                cloud_user_id=cloud_user_id,
                role=str(membership["role"]),
            )
            local_key_version = int(context.get("key_version") or 0)
            if key_version < local_key_version:
                raise PermissionDenied(
                    "remote organization key version rollback denied"
                )
            if key_version > local_key_version:
                pass
            else:
                service.resolve_cloud_context(
                    organization_id, cloud_user_id
                )
                _bind_cloud_device_session(cloud, context)
                return jsonify({
                    "organization_id": organization_id,
                    "device_id": context["device_id"],
                    "status": "active",
                    "key_version": context["key_version"],
                })

        envelopes = cloud.client.select(
            "key_envelopes",
            cloud.access_token(),
            query={
                "select": (
                    "organization_id,device_id,key_version,key_algorithm,"
                    "ephemeral_public_key,nonce,ciphertext"
                ),
                "organization_id": f"eq.{organization_id}",
                "device_id": f"eq.{context['device_id']}",
                "key_version": f"eq.{key_version}",
                "order": "key_version.desc",
                "limit": "1",
            },
        )
        if len(envelopes) != 1:
            raise PermissionDenied("organization key envelope unavailable")
        remote_envelope = dict(envelopes[0])
        normalized_envelope = {
            "organization_id": remote_envelope.get("organization_id"),
            "device_id": remote_envelope.get("device_id"),
            "key_version": remote_envelope.get("key_version"),
            "key_algorithm": remote_envelope.get("key_algorithm"),
            "ephemeral_public_key": base64.urlsafe_b64encode(
                _bytea(
                    remote_envelope.get("ephemeral_public_key"),
                    "信封临时公钥",
                )
            ).decode("ascii").rstrip("="),
            "nonce": base64.urlsafe_b64encode(
                _bytea(remote_envelope.get("nonce"), "信封 nonce")
            ).decode("ascii").rstrip("="),
            "ciphertext": base64.urlsafe_b64encode(
                _bytea(remote_envelope.get("ciphertext"), "信封密文")
            ).decode("ascii").rstrip("="),
        }
        active = service.activate_cloud_device_context(
            context,
            remote_device=remote_device,
            envelope=normalized_envelope,
            expected_key_version=key_version,
            role=str(membership["role"]),
        )
        _bind_cloud_device_session(cloud, active)
        return jsonify({
            "organization_id": organization_id,
            "device_id": active["device_id"],
            "status": "active",
            "key_version": active["key_version"],
        })

    @bp.post("/devices/<device_id>/approve")
    def approve_cloud_device(device_id):
        data = request.get_json(silent=True) or {}
        organization_id = str(data.get("organization_id") or "").strip()
        if not organization_id:
            return jsonify({"error": "organization_id 必填"}), 400
        cloud = _cloud_required()
        rows = cloud.client.select(
            "devices",
            cloud.access_token(),
            query={
                "select": (
                    "id,organization_id,user_id,key_algorithm,device_kind,"
                    "public_key,status"
                ),
                "organization_id": f"eq.{organization_id}",
                "id": f"eq.{device_id}",
                "limit": "1",
            },
        )
        if not rows:
            return jsonify({"error": "待配对设备不存在"}), 404
        remote_device = dict(rows[0])
        encoded = str(remote_device.get("public_key") or "")
        if not encoded.startswith("\\x"):
            return jsonify({"error": "设备公钥编码无效"}), 409
        try:
            remote_device["public_key"] = bytes.fromhex(encoded[2:])
        except ValueError:
            return jsonify({"error": "设备公钥编码无效"}), 409
        context = service_provider().resolve_cloud_context(
            organization_id,
            cloud.user_id(),
        )
        result = cloud.rpc(
            "pair_device",
            service_provider().build_cloud_device_pairing(
                context,
                remote_device,
            ),
        )
        return jsonify({"paired": True, "result": result})

    @bp.post("/members/invite")
    def invite_cloud_member():
        data = request.get_json(silent=True) or {}
        organization_id = str(data.get("organization_id") or "").strip()
        email = str(data.get("email") or "").strip().lower()
        role = str(data.get("role") or "").strip().lower()
        if not organization_id or not email or not role:
            return jsonify({"error": "organization_id、email、role 必填"}), 400
        cloud = _cloud_required()
        result = cloud.client.invoke(
            "invite-member",
            {
                "organization_id": organization_id,
                "email": email,
                "role": role,
            },
            cloud.access_token(),
        )
        return jsonify(result), 202

    @bp.get("/members/invitations")
    def list_cloud_member_invitations():
        organization_id = _canonical_request_uuid(
            request.args.get("organization_id"),
            "organization_id",
        )
        rows = _cloud_required().rpc(
            "list_member_invitations",
            {"p_organization_id": organization_id},
        ) or []
        if not isinstance(rows, list) or len(rows) > 200:
            raise ValueError("邀请列表响应无效")
        allowed = {
            "invitation_id",
            "invitation_role",
            "invitation_status",
            "expires_at",
            "created_at",
            "finalized_at",
            "cancelled_at",
        }
        invitations = [
            {
                key: row.get(key)
                for key in allowed
            }
            for row in rows
            if isinstance(row, dict)
        ]
        if len(invitations) != len(rows):
            raise ValueError("邀请列表响应无效")
        return jsonify({"invitations": invitations})

    @bp.delete("/members/invitations/<invitation_id>")
    def cancel_cloud_member_invitation(invitation_id):
        invitation_id = _canonical_request_uuid(
            invitation_id,
            "invitation_id",
        )
        cancelled = _cloud_required().rpc(
            "cancel_member_invitation",
            {"p_invitation_id": invitation_id},
        )
        if not isinstance(cancelled, bool):
            raise ValueError("取消邀请响应无效")
        return jsonify({"cancelled": cancelled})

    @bp.post("/sync/run")
    def run_cloud_sync():
        cloud = _cloud_required()
        service = service_provider()
        requested_org = str(
            (request.get_json(silent=True) or {}).get("organization_id") or ""
        ).strip()
        if not requested_org:
            return jsonify({"error": "organization_id 必填"}), 400
        context = service.resolve_cloud_context(
            requested_org,
            cloud.user_id(),
        )
        remote_devices = _remote_cloud_devices(cloud, requested_org)
        own_remote = [
            item for item in remote_devices
            if item.get("id") == context["device_id"]
            and item.get("user_id") == cloud.user_id()
            and item.get("status") == "active"
            and item.get("key_algorithm") == "p256"
            and item.get("device_kind") == "desktop"
        ]
        if len(own_remote) != 1:
            raise PermissionDenied("active remote device required")
        sync_devices = _sync_cloud_devices(cloud, requested_org)
        if not any(
            item["device_id"] == context["device_id"]
            for item in sync_devices
        ):
            raise PermissionDenied("active sync device discovery required")
        service.import_cloud_device_metadata(context, sync_devices)
        return jsonify(
            run_sync_cycle(
                service,
                context,
                SupabaseCoordinator(cloud),
            )
        )

    @bp.post("/sync/bootstrap-snapshot")
    def bootstrap_cloud_snapshot():
        data = request.get_json(silent=True) or {}
        if data.get("confirm_empty_cloud") is not True:
            return jsonify({
                "error": "必须显式确认目标组织云端为空"
            }), 400
        context = _personal_context(
            str(data.get("organization_id") or "").strip()
        )
        cloud = _cloud_required()
        service = service_provider()
        try:
            manifest = service.prepare_initial_snapshot_import(
                context["organization_id"],
                context["user_id"],
            )
        except ValueError as error:
            return jsonify({"error": str(error)}), 409
        service.begin_initial_snapshot_import(
            context["organization_id"], context["user_id"], manifest
        )
        remote_import = cloud.rpc(
            "begin_snapshot_import",
            {
                "organization_id": context["organization_id"],
                "expected_count": manifest["expected_count"],
                "manifest_hash": manifest["manifest_hash"],
            },
        )
        try:
            result = service.queue_initial_snapshot(
                context["organization_id"],
                context["user_id"],
            )
        except ValueError as error:
            if int(remote_import.get("accepted_count") or 0) == 0:
                aborted = cloud.rpc(
                    "abort_snapshot_import",
                    {"import_id": remote_import["import_id"]},
                )
                if aborted.get("status") == "aborted":
                    service.abort_initial_snapshot_import(
                        context["organization_id"],
                        context["user_id"],
                        manifest["manifest_hash"],
                    )
            return jsonify({
                "error": str(error),
                "import_id": remote_import["import_id"],
                "resumable": (
                    remote_import.get("status") == "staging"
                    and int(remote_import.get("accepted_count") or 0) > 0
                ),
            }), 409
        return jsonify({
            "organization_id": context["organization_id"],
            "staged": True,
            "expected_count": manifest["expected_count"],
            "manifest_hash": manifest["manifest_hash"],
            "import": remote_import,
            **result,
        }), 202 if result.get("queued") else 200

    @bp.post("/sync/bootstrap-snapshot/complete")
    def complete_cloud_snapshot():
        data = request.get_json(silent=True) or {}
        context = _personal_context(
            str(data.get("organization_id") or "").strip()
        )
        service = service_provider()
        try:
            manifest = service.prepare_initial_snapshot_completion(
                context["organization_id"],
                context["user_id"],
            )
        except ValueError as error:
            return jsonify({"error": str(error)}), 409
        cloud = _cloud_required()
        remote_import = cloud.rpc(
            "begin_snapshot_import",
            {
                "organization_id": context["organization_id"],
                "expected_count": manifest["expected_count"],
                "manifest_hash": manifest["manifest_hash"],
            },
        )
        completed = cloud.rpc(
            "complete_snapshot_import",
            {"import_id": remote_import["import_id"]},
        )
        service.finish_initial_snapshot_import(
            context["organization_id"],
            context["user_id"],
            manifest["manifest_hash"],
        )
        return jsonify({
            "organization_id": context["organization_id"],
            "manifest_hash": manifest["manifest_hash"],
            "expected_count": manifest["expected_count"],
            "import": completed,
        })

    @bp.get("/sync/status")
    def cloud_sync_status():
        service = service_provider()
        organization_id = str(g.v9_asserted_organization_id)
        mode = str(g.v9_asserted_context_mode)
        if mode == "cloud":
            cloud = _cloud_required()
            cloud.access_token()
            context = service.resolve_cloud_context(
                organization_id,
                cloud.user_id(),
            )
            return jsonify(
                service.repository.get_sync_status(
                    context["organization_id"]
                )
                | {"configured": True, "initialized": True}
            )
        context = _personal_context(organization_id)
        return jsonify(
            service.repository.get_sync_status(context["organization_id"])
            | {
                "configured": _cloud() is not None,
                "initialized": True,
            }
        )

    @bp.post("/conflicts/<conflict_id>/resolve")
    def resolve_cloud_conflict(conflict_id):
        data = request.get_json(silent=True) or {}
        event = validate_ciphertext_event(data.get("resolution_event"))
        event_org = str(event["organization_id"])
        body_org = str(data.get("organization_id") or "").strip()
        if body_org and body_org != event_org:
            raise PermissionDenied(
                "conflict resolution organization mismatch"
            )
        context = _business_context(event_org)
        record_id = str(event["record_id"])
        repository = service_provider().repository
        sync_block = repository.get_sync_block(
            context["organization_id"], record_id
        )
        local_conflict = repository.get_conflict(conflict_id)
        local_conflict_matches = (
            local_conflict is None
            or (
                local_conflict["organization_id"]
                == context["organization_id"]
                and local_conflict["record_id"] == record_id
                and local_conflict["state"] == "open"
            )
        )
        service_provider().validate_local_conflict_resolution_event(
            context["organization_id"],
            context["user_id"],
            event,
        )
        result = _cloud_required().rpc(
            "resolve_conflict",
            {
                "conflict_id": conflict_id,
                "expected_head_version_id": str(
                    data.get("expected_head_version_id") or ""
                ),
                "resolution_event": event,
            },
        )
        if not isinstance(result, dict):
            raise ValueError("invalid conflict resolution response")
        if str(result.get("resolved_conflict_id") or "") != str(conflict_id):
            raise ValueError("conflict resolution identity mismatch")
        cloud_head_version_id = str(result.get("head_version_id") or "")
        resolved_version_id = str(result.get("version_id") or "")
        try:
            canonical_head = str(uuid.UUID(cloud_head_version_id))
            canonical_version = str(uuid.UUID(resolved_version_id))
        except (ValueError, AttributeError, TypeError):
            raise ValueError(
                "invalid conflict resolution head version"
            ) from None
        if (
            canonical_head != cloud_head_version_id
            or canonical_version != resolved_version_id
            or canonical_head != canonical_version
            or canonical_head != str(event["payload"]["version_id"])
        ):
            raise ValueError("conflict resolution head version mismatch")
        if (
            result.get("applied") is True
            and sync_block is not None
            and sync_block["resolved_at"] is None
            and sync_block["organization_id"] == context["organization_id"]
            and sync_block["record_id"] == record_id
            and local_conflict_matches
        ):
            repository.clear_sync_block(
                context["organization_id"],
                record_id,
                cloud_head_version_id=canonical_head,
            )
        return jsonify(result)

    @bp.post("/organizations/bootstrap")
    def bootstrap():
        data = request.get_json(silent=True) or {}
        required = ("name", "device_name")
        if any(not str(data.get(key, "")).strip() for key in required):
            return jsonify({"error": "name、device_name 必填"}), 400
        context = service_provider().get_or_create_personal_context()
        result = context | {"role": "owner", "key_version": 1}
        return jsonify(result), 201

    @bp.post("/organizations/bootstrap/acknowledge")
    def acknowledge_personal_recovery():
        data = request.get_json(silent=True) or {}
        organization_id = _canonical_request_uuid(
            data.get("organization_id"),
            "organization_id",
        )
        result = service_provider().acknowledge_personal_recovery(
            organization_id
        )
        return jsonify({
            "mode": "personal",
            "organization_id": result["organization_id"],
            "recovery_acknowledged": bool(
                result.get("recovery_acknowledged")
            ),
        })

    @bp.get("/situation")
    def situation():
        if situation_provider is None:
            return jsonify({"regions": [], "wire": [], "status": "unavailable"})
        return jsonify(situation_provider())

    @bp.post("/evidence/archive-news")
    def archive_news():
        data = request.get_json(silent=True) or {}
        article = data.get("article")
        if not isinstance(article, dict):
            return jsonify({"error": "article 必填"}), 400
        service = service_provider()
        context = _business_context(
            str(data.get("organization_id") or ""),
            create=True,
        )
        result = service.archive_news_evidence(context, article)
        if "recovery_code" in context:
            result["recovery_code"] = context["recovery_code"]
        return jsonify(result), 201 if result["created"] else 200

    @bp.get("/evidence")
    def evidence():
        service = service_provider()
        context = _business_context(
            str(request.args.get("organization_id") or ""),
            optional=True,
        )
        if context is None:
            return jsonify({"evidence": [], "needs_bootstrap": True})
        return jsonify({"evidence": service.list_evidence(context)})

    @bp.get("/claims")
    def claims():
        service = service_provider()
        context = _business_context(
            str(request.args.get("organization_id") or ""),
            optional=True,
        )
        if context is None:
            return jsonify({"claims": [], "needs_bootstrap": True})
        return jsonify({"claims": service.list_claims(context)})

    @bp.post("/claims")
    def create_claim():
        data = request.get_json(silent=True) or {}
        service = service_provider()
        context = _business_context(
            str(data.get("organization_id") or ""),
            create=True,
        )
        result = service.create_claim(context, data)
        if "recovery_code" in context:
            result["recovery_code"] = context["recovery_code"]
        return jsonify(result), 201

    @bp.get("/alert-rules")
    def alert_rules():
        service = service_provider()
        context = _business_context(
            str(request.args.get("organization_id") or ""),
            optional=True,
        )
        if context is None:
            return jsonify({"rules": [], "needs_bootstrap": True})
        return jsonify({"rules": service.list_alert_rules(context)})

    @bp.post("/alert-rules")
    def save_alert_rule():
        data = request.get_json(silent=True) or {}
        service = service_provider()
        context = _business_context(
            str(data.get("organization_id") or ""),
            create=True,
        )
        result = service.save_alert_rule(context, data)
        if "recovery_code" in context:
            result["recovery_code"] = context["recovery_code"]
        return jsonify(result), 200 if data.get("record_id") else 201

    @bp.get("/alert-rules/evaluate")
    def evaluate_rules():
        service = service_provider()
        context = _business_context(
            str(request.args.get("organization_id") or ""),
            optional=True,
        )
        rules = service.list_alert_rules(context) if context else []
        articles = list(news_provider() or []) if news_provider else []
        return jsonify(evaluate_alert_rules(rules, articles))

    @bp.get("/graph")
    def graph():
        service = service_provider()
        context = _business_context(
            str(request.args.get("organization_id") or ""),
            optional=True,
        )
        if context is None:
            return jsonify({"entities": [], "relations": []})
        return jsonify(service.get_graph(context))

    @bp.post("/graph/entities")
    def create_graph_entity():
        data = request.get_json(silent=True) or {}
        service = service_provider()
        context = _business_context(
            str(data.get("organization_id") or ""),
            create=True,
        )
        result = service.create_graph_entity(context, data)
        if "recovery_code" in context:
            result["recovery_code"] = context["recovery_code"]
        return jsonify(result), 201

    @bp.post("/graph/relations")
    def create_graph_relation():
        data = request.get_json(silent=True) or {}
        service = service_provider()
        context = _business_context(
            str(data.get("organization_id") or ""),
            create=True,
        )
        result = service.create_graph_relation(context, data)
        if "recovery_code" in context:
            result["recovery_code"] = context["recovery_code"]
        return jsonify(result), 201

    @bp.get("/geo-events")
    def geo_events():
        service = service_provider()
        context = _business_context(
            str(request.args.get("organization_id") or ""),
            optional=True,
        )
        if context is None:
            return jsonify({"events": []})
        return jsonify(
            {
                "events": service.list_geo_events(
                    context, request.args.get("hours", 120, type=int)
                )
            }
        )

    @bp.post("/geo-events")
    def create_geo_event():
        data = request.get_json(silent=True) or {}
        service = service_provider()
        context = _business_context(
            str(data.get("organization_id") or ""),
            create=True,
        )
        result = service.create_geo_event(context, data)
        if "recovery_code" in context:
            result["recovery_code"] = context["recovery_code"]
        return jsonify(result), 201

    @bp.get("/alerts")
    def alerts():
        service = service_provider()
        context = _business_context(
            str(request.args.get("organization_id") or ""),
            optional=True,
        )
        return jsonify(
            {"alerts": service.list_alerts(context) if context else []}
        )

    @bp.post("/alerts/materialize")
    def materialize_alerts():
        data = request.get_json(silent=True) or {}
        service = service_provider()
        context = _business_context(
            str(data.get("organization_id") or ""),
            create=True,
        )
        rules = service.list_alert_rules(context)
        articles = list(news_provider() or []) if news_provider else []
        result = service.materialize_rule_hits(context, rules, articles)
        if "recovery_code" in context:
            result["recovery_code"] = context["recovery_code"]
        return jsonify(result)

    @bp.post("/alerts/<record_id>/action")
    def triage_alert(record_id):
        data = request.get_json(silent=True) or {}
        service = service_provider()
        context = _business_context(
            str(data.get("organization_id") or ""),
            create=True,
        )
        result = service.triage_alert(
            context,
            record_id,
            action=str(data.get("action") or ""),
            expected_version=int(data.get("version") or 0),
            value=data,
        )
        return jsonify(result)

    @bp.get("/cases")
    def cases():
        service = service_provider()
        context = _business_context(
            str(request.args.get("organization_id") or ""),
            optional=True,
        )
        return jsonify(
            {"cases": service.list_cases(context) if context else []}
        )

    @bp.patch("/cases/<record_id>")
    def update_case(record_id):
        data = request.get_json(silent=True) or {}
        service = service_provider()
        context = _business_context(
            str(data.get("organization_id") or ""),
            create=True,
        )
        result = service.update_case(
            context,
            record_id,
            expected_version=int(data.get("version") or 0),
            changes=data.get("changes")
            if isinstance(data.get("changes"), dict)
            else {},
        )
        return jsonify(result)

    @bp.get("/jobs")
    def jobs():
        service = service_provider()
        context = _business_context(
            str(request.args.get("organization_id") or ""),
            optional=True,
        )
        return jsonify(
            {"jobs": service.list_agent_jobs(context) if context else []}
        )

    @bp.post("/jobs")
    def create_job():
        data = request.get_json(silent=True) or {}
        service = service_provider()
        context = _business_context(
            str(data.get("organization_id") or ""),
            create=True,
        )
        result = service.create_agent_job(context, data)
        if "recovery_code" in context:
            result["recovery_code"] = context["recovery_code"]
        return jsonify(result), 201

    @bp.post("/jobs/<record_id>/action")
    def control_job(record_id):
        data = request.get_json(silent=True) or {}
        service = service_provider()
        context = _business_context(
            str(data.get("organization_id") or ""),
            create=True,
        )
        action = str(data.get("action") or "")
        if action == "execute_phase":
            if agent_phase_executor is None:
                return jsonify({"error": "本地 AI 阶段执行器未启用"}), 503
            result = service.execute_agent_job_phase(
                context,
                record_id,
                expected_version=int(data.get("version") or 0),
                executor=agent_phase_executor,
            )
            if result["execution_error"]:
                result["error"] = result["execution_error"]["message"]
                return jsonify(result), 502
            return jsonify(result)
        return jsonify(
            service.control_agent_job(
                context,
                record_id,
                action=action,
                expected_version=int(data.get("version") or 0),
                value=data,
            )
        )

    @bp.get("/scenarios")
    def scenarios():
        service = service_provider()
        context = _business_context(
            str(request.args.get("organization_id") or ""),
            optional=True,
        )
        return jsonify(
            {
                "scenarios": service.list_scenarios(context)
                if context
                else []
            }
        )

    @bp.post("/scenarios")
    def create_scenario():
        data = request.get_json(silent=True) or {}
        service = service_provider()
        context = _business_context(
            str(data.get("organization_id") or ""),
            create=True,
        )
        result = service.create_scenario(context, data)
        if "recovery_code" in context:
            result["recovery_code"] = context["recovery_code"]
        return jsonify(result), 201

    @bp.patch("/scenarios/<record_id>")
    def update_scenario(record_id):
        data = request.get_json(silent=True) or {}
        service = service_provider()
        context = _business_context(
            str(data.get("organization_id") or ""),
            create=True,
        )
        result = service.update_scenario(
            context,
            record_id,
            expected_version=int(data.get("version") or 0),
            changes=data.get("changes")
            if isinstance(data.get("changes"), dict)
            else {},
        )
        return jsonify(result)

    @bp.get("/documents")
    def documents():
        service = service_provider()
        context = _business_context(
            str(request.args.get("organization_id") or ""),
            create=True,
        )
        return jsonify({"documents": service.list_documents(context)})

    @bp.post("/documents")
    def create_document():
        data = request.get_json(silent=True) or {}
        service = service_provider()
        context = _business_context(
            str(data.get("organization_id") or ""),
            create=True,
        )
        result = service.create_document(context, data)
        if "recovery_code" in context:
            result["recovery_code"] = context["recovery_code"]
        return jsonify(result), 201

    @bp.patch("/documents/<record_id>")
    def update_document(record_id):
        data = request.get_json(silent=True) or {}
        service = service_provider()
        context = _business_context(
            str(data.get("organization_id") or ""),
            create=True,
        )
        return jsonify(
            service.update_document(
                context,
                record_id,
                expected_version=int(data.get("version") or 0),
                changes=data.get("changes")
                if isinstance(data.get("changes"), dict)
                else {},
            )
        )

    @bp.get("/documents/<record_id>/export.<output_format>")
    def export_document(record_id, output_format):
        service = service_provider()
        context = _business_context(
            str(request.args.get("organization_id") or ""),
            create=True,
        )
        payload, filename = service.export_document(
            context, record_id, output_format
        )
        mimetype = (
            "application/vnd.openxmlformats-officedocument."
            "wordprocessingml.document"
            if output_format.lower() == "docx"
            else "application/pdf"
        )
        return send_file(
            BytesIO(payload),
            mimetype=mimetype,
            as_attachment=True,
            download_name=filename,
        )

    @bp.get("/publications")
    def publications():
        service = service_provider()
        context = _business_context(
            str(request.args.get("organization_id") or ""),
            create=True,
        )
        return jsonify(
            {"publications": service.list_publication_items(context)}
        )

    @bp.post("/publications")
    def create_publication():
        data = request.get_json(silent=True) or {}
        service = service_provider()
        context = _business_context(
            str(data.get("organization_id") or ""),
            create=True,
        )
        document_id = str(data.get("document_id") or "").strip()
        if not document_id:
            return jsonify({"error": "document_id 必填"}), 400
        return jsonify(
            service.create_publication_item(context, document_id)
        ), 201

    @bp.patch("/publications/<record_id>")
    def move_publication(record_id):
        data = request.get_json(silent=True) or {}
        service = service_provider()
        context = _business_context(
            str(data.get("organization_id") or ""),
            create=True,
        )
        return jsonify(
            service.move_publication_item(
                context,
                record_id,
                expected_version=int(data.get("version") or 0),
                status=str(data.get("status") or ""),
                position=int(data.get("position") or 0),
            )
        )

    @bp.post("/publications/<record_id>/sign")
    def sign_publication(record_id):
        data = request.get_json(silent=True) or {}
        service = service_provider()
        context = _business_context(
            str(data.get("organization_id") or ""),
            create=True,
        )
        return jsonify(
            service.sign_publication_item(
                context,
                record_id,
                expected_version=int(data.get("version") or 0),
            )
        )

    @bp.post("/publications/<record_id>/recall")
    def recall_publication(record_id):
        data = request.get_json(silent=True) or {}
        service = service_provider()
        context = _business_context(
            str(data.get("organization_id") or ""),
            create=True,
        )
        return jsonify(
            service.recall_publication_item(
                context,
                record_id,
                expected_version=int(data.get("version") or 0),
                reason=str(data.get("reason") or ""),
            )
        )

    @bp.get("/publications/<record_id>/export.<output_format>")
    def export_publication(record_id, output_format):
        service = service_provider()
        context = _business_context(
            str(request.args.get("organization_id") or ""),
            create=True,
        )
        payload, filename = service.export_publication(
            context, record_id, output_format
        )
        mimetype = (
            "application/vnd.openxmlformats-officedocument."
            "wordprocessingml.document"
            if output_format.lower() == "docx"
            else "application/pdf"
        )
        return send_file(
            BytesIO(payload),
            mimetype=mimetype,
            as_attachment=True,
            download_name=filename,
        )

    @bp.get("/audit-events")
    def audit_events():
        service = service_provider()
        context = _business_context(
            str(request.args.get("organization_id") or ""),
            create=True,
        )
        return jsonify({"events": service.list_audit_events(context)})

    @bp.post("/records")
    def create_record():
        data = request.get_json(silent=True) or {}
        context = _business_context(
            str(data.get("organization_id", "")),
            str(data.get("device_id", "")),
        )
        result = service_provider().create_record(
            context["organization_id"],
            context["user_id"],
            context["device_id"],
            str(data.get("record_type", "")),
            data.get("content"),
        )
        return jsonify(result), 201

    @bp.get("/records/<record_id>")
    def read_record(record_id):
        context = _business_context(
            str(request.args.get("organization_id", ""))
        )
        result = service_provider().read_record(
            context["organization_id"],
            context["user_id"],
            record_id,
        )
        return jsonify(result)

    @bp.put("/records/<record_id>")
    def update_record(record_id):
        data = request.get_json(silent=True) or {}
        context = _business_context(
            str(data.get("organization_id", "")),
            str(data.get("device_id", "")),
        )
        result = service_provider().update_record(
            context["organization_id"],
            context["user_id"],
            context["device_id"],
            record_id,
            expected_version=int(data.get("expected_version", 0)),
            content=data.get("content"),
        )
        return jsonify(result)

    @bp.get("/sync/outbox")
    def outbox():
        context = _business_context(
            str(request.args.get("organization_id", ""))
        )
        if not service_provider().authorize(
            context["organization_id"],
            context["user_id"],
            "record.read",
        ):
            raise PermissionDenied("record.read denied")
        return jsonify({"events": service_provider().export_outbox(
            context["organization_id"]
        )})

    @bp.post("/organizations/<org_id>/members")
    def add_member(org_id):
        data = request.get_json(silent=True) or {}
        context = _personal_context(org_id)
        result = service_provider().add_member(
            org_id,
            context["user_id"],
            str(data.get("user_id", "")),
            str(data.get("role", "")),
        )
        return jsonify(result), 201

    @bp.delete("/organizations/<org_id>/members/<user_id>")
    def revoke_member(org_id, user_id):
        context = _personal_context(org_id)
        return jsonify(service_provider().revoke_member(
            org_id, context["user_id"], user_id
        ))

    @bp.post("/organizations/<org_id>/devices/pair")
    def pair_device(org_id):
        data = request.get_json(silent=True) or {}
        context = _personal_context(org_id)
        encoded_key = str(data.get("public_key", ""))
        padding = "=" * ((4 - len(encoded_key) % 4) % 4)
        public_key = base64.urlsafe_b64decode(encoded_key + padding)
        result = service_provider().pair_device(
            org_id,
            context["user_id"],
            str(data.get("user_id", "")),
            str(data.get("device_name", "")),
            public_key,
        )
        return jsonify(result), 201

    @bp.post("/pairing-sessions")
    def create_pairing_session():
        data = request.get_json(silent=True) or {}
        context = _personal_context(
            str(data.get("organization_id", "")),
            str(data.get("device_id", "")),
        )
        result = service_provider().create_pairing_session(
            {
                "organization_id": context["organization_id"],
                "user_id": context["user_id"],
                "device_id": context["device_id"],
            },
            target_user_id=str(data.get("user_id", "")),
            device_name=str(data.get("device_name", "")),
            ttl_seconds=int(data.get("ttl_seconds", 300)),
        )
        return jsonify(result), 201

    @bp.post("/pairing-sessions/claim")
    def claim_pairing_session():
        data = request.get_json(silent=True) or {}
        encoded_key = str(data.get("public_key", ""))
        padding = "=" * ((4 - len(encoded_key) % 4) % 4)
        public_key = base64.urlsafe_b64decode(encoded_key + padding)
        result = service_provider().claim_pairing_session(
            str(data.get("pairing_code", "")), public_key
        )
        return jsonify(result), 201

    @bp.post("/organizations/<org_id>/devices/recover")
    def recover_device(org_id):
        data = request.get_json(silent=True) or {}
        context = _personal_context(org_id)
        return jsonify(service_provider().recover_device(
            org_id,
            context["user_id"],
            str(data.get("device_name", "")),
            str(data.get("recovery_code", "")),
        )), 201

    @bp.delete("/organizations/<org_id>/devices/<device_id>")
    def revoke_device(org_id, device_id):
        context = _personal_context(org_id)
        return jsonify(service_provider().revoke_device(
            org_id, context["user_id"], device_id
        ))

    @bp.get("/organizations/<org_id>/conflicts")
    def conflicts(org_id):
        context = _business_context(org_id)
        return jsonify({"conflicts": service_provider().list_conflicts(
            org_id, context["user_id"]
        )})

    @bp.get("/organizations/<org_id>/diagnostics")
    def diagnostics(org_id):
        context = _business_context(org_id)
        payload = service_provider().export_diagnostic_bundle(
            org_id, context["user_id"]
        )
        return send_file(
            BytesIO(payload),
            mimetype="application/zip",
            as_attachment=True,
            download_name="DefenseTracker-V9-diagnostics.zip",
        )

    @bp.post("/organizations/<org_id>/backups")
    def create_backup(org_id):
        context = _business_context(org_id)
        result = service_provider().create_local_backup(
            org_id, context["user_id"]
        )
        return jsonify(result), 201

    @bp.get("/diagnostics/export")
    def personal_diagnostics():
        context = _business_context(
            str(request.args.get("organization_id") or ""),
            create=True,
        )
        payload = service_provider().export_diagnostic_bundle(
            context["organization_id"], context["user_id"]
        )
        return send_file(
            BytesIO(payload),
            mimetype="application/zip",
            as_attachment=True,
            download_name="DefenseTracker-V9-diagnostics.zip",
        )

    @bp.post("/backups")
    def personal_backup():
        data = request.get_json(silent=True) or {}
        context = _business_context(
            str(data.get("organization_id") or ""),
            create=True,
        )
        return jsonify(service_provider().create_local_backup(
            context["organization_id"], context["user_id"]
        )), 201

    @bp.post("/sync/push")
    def sync_push():
        data = request.get_json(silent=True) or {}
        forbidden = {"content", "body", "plaintext", "original_text"}
        if forbidden.intersection(data):
            return jsonify({"error": "云同步接口只接受密文载荷"}), 400
        event = data.get("event")
        if not isinstance(event, dict):
            return jsonify({"error": "密文 event 必填"}), 400
        body_org = str(data.get("organization_id") or "").strip()
        event_org = str(event.get("organization_id") or "").strip()
        if body_org and event_org and body_org != event_org:
            raise PermissionDenied("sync event organization mismatch")
        context = _business_context(event_org or body_org)
        result = service_provider().apply_remote_event(
            context["organization_id"],
            context["user_id"],
            event,
            remote_cursor=data.get("remote_cursor"),
        )
        return jsonify(result)

    return bp
