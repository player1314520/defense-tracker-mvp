"""V9 organization, encryption, authorization and sync orchestration."""
from __future__ import annotations

import copy
import hashlib
import hmac
import base64
import binascii
import json
import os
import re
import secrets
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import (
    DPAPI_MASTER_KEY_MAGIC,
    RecordEnvelope,
    create_device_keypair,
    create_recovery_envelope,
    decrypt_local_secret,
    decrypt_record,
    encrypt_local_secret,
    encrypt_record,
    generate_org_key,
    open_org_key_for_p256,
    recover_org_key,
    rewrap_record_data_key,
    seal_org_key_for_device,
    seal_org_key_for_p256,
    protect_local_master_key,
    unprotect_local_master_key,
)
from .ai_credentials import (
    EncryptedAiCredential,
    InMemoryAiCredential,
    create_desktop_credential_keypair,
    decrypt_api_credential,
    encrypt_api_credential,
    load_desktop_credential_private_key,
    rewrap_credential_for_new_device,
)
from .cloud import validate_ciphertext_event
from .alerts import evaluate_alert_rules, normalize_alert_rule
from .errors import (
    InvalidRecordType,
    NotFound,
    PermissionDenied,
    UntrustedSyncEvent,
    VersionConflict,
)
from .rbac import ROLES, role_allows
from .repository import RECORD_TYPES, V9Repository
from .orchestration import (
    apply_scenario_changes,
    new_agent_job,
    new_scenario,
    transition_agent_job,
)
from .publication import (
    BOARD_STATUSES,
    apply_document_changes,
    build_document_docx,
    build_document_pdf,
    build_source_index,
    evidence_ids_for_document,
    new_document,
    new_publication_item,
    safe_filename,
    signed_publication_content,
    validate_document,
)
from .workflow import (
    ALERT_ACTIONS,
    apply_case_changes,
    new_case_from_alert,
    normalize_claim,
    normalize_entity,
    normalize_geo_event,
    normalize_relation,
)
from .diagnostics import build_diagnostic_bundle
from .backup import backup_database


_CREATE_PERMISSIONS = {
    "source": "evidence.create",
    "evidence": "evidence.create",
    "claim": "case.analyze",
    "entity": "case.analyze",
    "relation": "case.analyze",
    "geo_event": "case.analyze",
    "alert_rule": "rules.manage",
    "alert": "case.analyze",
    "case": "case.analyze",
    "job": "scenario.run",
    "scenario": "scenario.run",
    "document": "document.edit",
    "publication_item": "layout.edit",
    "audit_event": "audit.write",
}
_WORKFLOW_RECORD_TYPES = {"publication_item", "audit_event"}
_PERSONAL_CONTEXT_PROFILE = "default_personal_context"
_PERSONAL_RECOVERY_PROFILE = "default_personal_recovery_state"


@contextmanager
def _exclusive_file_lock(
    lock_path: Path,
    *,
    error_message: str,
):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as handle:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        deadline = time.monotonic() + 30
        if os.name == "nt":
            import msvcrt

            while True:
                handle.seek(0)
                try:
                    msvcrt.locking(
                        handle.fileno(), msvcrt.LK_NBLCK, 1
                    )
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError(error_message) from None
                    time.sleep(0.05)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            while True:
                try:
                    fcntl.flock(
                        handle.fileno(),
                        fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError(error_message) from None
                    time.sleep(0.05)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class V9Service:
    def __init__(self, database_path: Path, local_master_key_path: Path):
        self.database_path = Path(database_path)
        self.local_master_key_path = Path(local_master_key_path)
        self.repository = V9Repository(self.database_path)
        self._master_key = self._load_or_create_master_key()
        self._personal_context_lock = threading.Lock()
        self._cloud_context_lock = threading.Lock()
        self._evidence_archive_lock = threading.Lock()
        self._workflow_lock = threading.Lock()

    @contextmanager
    def _personal_recovery_guard(self):
        """Serialize bootstrap/ack across threads and desktop processes."""
        lock_path = Path(
            f"{self.database_path}.personal-recovery.lock"
        )
        with self._personal_context_lock:
            with _exclusive_file_lock(
                lock_path,
                error_message="personal recovery lock unavailable",
            ):
                yield

    def _load_or_create_master_key(self) -> bytes:
        path = self.local_master_key_path
        path.parent.mkdir(parents=True, exist_ok=True)
        with _exclusive_file_lock(
            Path(f"{path}.init.lock"),
            error_message="local master key lock unavailable",
        ):
            if path.exists():
                payload = path.read_bytes()
                if (
                    os.name == "nt"
                    and payload.startswith(DPAPI_MASTER_KEY_MAGIC)
                ):
                    key = unprotect_local_master_key(payload)
                    self._harden_matching_legacy_master_keys(key, payload)
                    return key
                if len(payload) != 32:
                    raise ValueError("invalid local V9 master key")
                key = payload
                if os.name == "nt":
                    protected = protect_local_master_key(key)
                    self._write_master_key_payload(path, protected)
                    self._harden_matching_legacy_master_keys(
                        key, protected
                    )
                return key
            key = os.urandom(32)
            payload = (
                protect_local_master_key(key)
                if os.name == "nt"
                else key
            )
            self._write_master_key_payload(path, payload)
            return key

    @staticmethod
    def _write_master_key_payload(path: Path, payload: bytes) -> None:
        temporary = path.with_name(
            f".{path.name}.{uuid.uuid4().hex}.tmp"
        )
        try:
            with temporary.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.chmod(temporary, 0o600)
            except OSError:
                pass
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def _harden_matching_legacy_master_keys(
        self, master_key: bytes, protected_payload: bytes
    ) -> None:
        """Atomically protect matching legacy copies after vault migration."""
        path = self.local_master_key_path
        if os.name != "nt" or path.name != ".v9_local_master.key":
            return
        candidates = {
            path.parent.parent / "config" / path.name,
            Path(__file__).resolve().parents[1] / path.name,
            Path(sys.executable).resolve().parent / path.name,
        }
        for candidate in candidates:
            if candidate == path or not candidate.is_file():
                continue
            legacy_payload = candidate.read_bytes()
            if legacy_payload.startswith(DPAPI_MASTER_KEY_MAGIC):
                continue
            if legacy_payload == master_key:
                self._write_master_key_payload(candidate, protected_payload)

    def export_diagnostic_bundle(
        self, organization_id: str, acting_user_id: str
    ) -> bytes:
        self._require(
            organization_id, acting_user_id, "system.configure"
        )
        runtime_root = self.database_path.parent.parent
        release_manifest = (
            Path(sys.executable).parent / "release-manifest.json"
            if getattr(sys, "frozen", False)
            else None
        )
        return build_diagnostic_bundle(
            database_path=self.database_path,
            organization_id=organization_id,
            config_dir=self.local_master_key_path.parent,
            logs_dir=runtime_root / "logs",
            release_manifest_path=release_manifest,
        )

    def create_local_backup(
        self, organization_id: str, acting_user_id: str
    ) -> dict:
        self._require(
            organization_id, acting_user_id, "system.configure"
        )
        backup_dir = self.database_path.parent / "backups"
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        destination = backup_dir / f"v9-{timestamp}.sqlite3"
        backup_database(self.database_path, destination)
        return {
            "filename": destination.name,
            "bytes": destination.stat().st_size,
            "ciphertext_database": True,
            "plaintext_included": False,
        }

    @staticmethod
    def _org_secret_aad(org_id: str, key_version: int) -> bytes:
        return f"v9:local-org-key:1:{org_id}:{key_version}".encode()

    @staticmethod
    def _device_secret_aad(org_id: str, device_id: str) -> bytes:
        return f"v9:local-device-key:1:{org_id}:{device_id}".encode()

    def _store_org_key(self, org_id: str, key_version: int, org_key: bytes) -> None:
        nonce, ciphertext = encrypt_local_secret(
            self._master_key,
            org_key,
            self._org_secret_aad(org_id, key_version),
        )
        self.repository.put_local_secret(
            org_id, "org_key", org_id, key_version, nonce, ciphertext
        )

    def _load_org_key(self, org_id: str, key_version: int) -> bytes:
        row = self.repository.get_local_secret(
            org_id, "org_key", org_id, key_version
        )
        if row is None:
            raise PermissionDenied("organization key is not unlocked on this device")
        return decrypt_local_secret(
            self._master_key,
            row["nonce"],
            row["ciphertext"],
            self._org_secret_aad(org_id, key_version),
        )

    def _store_device_private_key(
        self, org_id: str, device_id: str, private_key: bytes
    ) -> None:
        nonce, ciphertext = encrypt_local_secret(
            self._master_key,
            private_key,
            self._device_secret_aad(org_id, device_id),
        )
        self.repository.put_local_secret(
            org_id, "device_private_key", device_id, 0, nonce, ciphertext
        )

    def bootstrap_organization(
        self, name: str, owner_user_id: str, device_name: str
    ) -> dict:
        org_id = str(uuid.uuid4())
        device_id = str(uuid.uuid4())
        org_key = generate_org_key()
        public_key, private_key = create_device_keypair()
        self.repository.create_organization(org_id, name)
        self.repository.add_membership(org_id, owner_user_id, "owner")
        self.repository.add_device(
            device_id,
            org_id,
            owner_user_id,
            device_name,
            public_key,
            key_algorithm="x25519",
            device_kind="desktop",
        )
        self._store_org_key(org_id, 1, org_key)
        self._store_device_private_key(org_id, device_id, private_key)
        device_envelope = seal_org_key_for_device(
            org_key,
            public_key,
            org_id=org_id,
            device_id=device_id,
            key_version=1,
        )
        self.repository.put_key_envelope(device_envelope)
        recovery_code, recovery_envelope = create_recovery_envelope(
            org_key, org_id, key_version=1
        )
        self.repository.put_recovery_envelope(org_id, 1, recovery_envelope)
        return {
            "organization_id": org_id,
            "device_id": device_id,
            "role": "owner",
            "key_version": 1,
            "recovery_code": recovery_code,
        }

    def get_personal_context(self) -> dict | None:
        return self.repository.get_profile(_PERSONAL_CONTEXT_PROFILE)

    @staticmethod
    def _personal_recovery_aad(organization_id: str) -> bytes:
        return (
            f"v9:pending-personal-recovery:1:{organization_id}"
        ).encode()

    def _pending_personal_recovery_code(
        self, context: dict
    ) -> str | None:
        state = self.repository.get_profile(_PERSONAL_RECOVERY_PROFILE)
        if state is None:
            return None
        if (
            state.get("version") != 1
            or state.get("organization_id") != context["organization_id"]
        ):
            raise ValueError("invalid personal recovery state")
        if state.get("state") == "acknowledged":
            return None
        if state.get("state") != "pending":
            raise ValueError("invalid personal recovery state")
        try:
            nonce = base64.b64decode(
                str(state["nonce"]), validate=True
            )
            ciphertext = base64.b64decode(
                str(state["ciphertext"]), validate=True
            )
            recovery_code = decrypt_local_secret(
                self._master_key,
                nonce,
                ciphertext,
                self._personal_recovery_aad(context["organization_id"]),
            ).decode("utf-8")
        except (
            KeyError,
            ValueError,
            UnicodeDecodeError,
            InvalidTag,
            binascii.Error,
        ) as error:
            raise ValueError("invalid personal recovery state") from error
        if not recovery_code:
            raise ValueError("invalid personal recovery state")
        return recovery_code

    def _persist_pending_personal_recovery(
        self, context: dict, recovery_code: str
    ) -> None:
        nonce, ciphertext = encrypt_local_secret(
            self._master_key,
            recovery_code.encode("utf-8"),
            self._personal_recovery_aad(context["organization_id"]),
        )
        self.repository.put_profile(
            _PERSONAL_RECOVERY_PROFILE,
            {
                "version": 1,
                "state": "pending",
                "organization_id": context["organization_id"],
                "user_id": context["user_id"],
                "device_id": context["device_id"],
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            },
        )

    def _recover_pending_personal_context(self) -> dict | None:
        state = self.repository.get_profile(_PERSONAL_RECOVERY_PROFILE)
        if state is None or state.get("state") != "pending":
            return None
        context = {
            "organization_id": str(state.get("organization_id") or ""),
            "user_id": str(state.get("user_id") or ""),
            "device_id": str(state.get("device_id") or ""),
        }
        organization = self.repository.get_organization(
            context["organization_id"]
        )
        membership = self.repository.get_membership(
            context["organization_id"], context["user_id"]
        )
        device = self.repository.get_device(context["device_id"])
        if (
            organization is None
            or membership is None
            or membership.get("status") != "active"
            or device is None
            or device.get("organization_id") != context["organization_id"]
            or device.get("user_id") != context["user_id"]
            or device.get("status") != "active"
        ):
            raise ValueError("invalid pending personal recovery context")
        self._pending_personal_recovery_code(context)
        self.repository.put_profile(_PERSONAL_CONTEXT_PROFILE, context)
        return context

    def personal_recovery_pending(self) -> bool:
        context = self.get_personal_context()
        if context is None:
            state = self.repository.get_profile(_PERSONAL_RECOVERY_PROFILE)
            return bool(state and state.get("state") == "pending")
        return self._pending_personal_recovery_code(context) is not None

    def get_or_create_personal_context(self) -> dict:
        with self._personal_recovery_guard():
            existing = self.get_personal_context()
            if existing:
                recovery_code = self._pending_personal_recovery_code(existing)
                return (
                    existing
                    if recovery_code is None
                    else existing | {
                        "recovery_pending": True,
                        "recovery_code": recovery_code,
                    }
                )
            existing = self._recover_pending_personal_context()
            if existing:
                recovery_code = self._pending_personal_recovery_code(existing)
                return existing | {
                    "recovery_pending": True,
                    "recovery_code": recovery_code,
                }
            boot = self.bootstrap_organization(
                "个人工作区", "local-owner", "本机桌面"
            )
            context = {
                "organization_id": boot["organization_id"],
                "user_id": "local-owner",
                "device_id": boot["device_id"],
            }
            self._persist_pending_personal_recovery(
                context, boot["recovery_code"]
            )
            self.repository.put_profile(_PERSONAL_CONTEXT_PROFILE, context)
            return context | {
                "recovery_pending": True,
                "recovery_code": boot["recovery_code"],
            }

    def acknowledge_personal_recovery(
        self, organization_id: str
    ) -> dict:
        with self._personal_recovery_guard():
            context = self.get_personal_context()
            if (
                context is None
                or context.get("organization_id") != organization_id
            ):
                raise PermissionDenied(
                    "local personal organization required"
                )
            state = self.repository.get_profile(_PERSONAL_RECOVERY_PROFILE)
            if state is None:
                return context | {
                    "recovery_acknowledged": True,
                    "legacy_context": True,
                }
            if (
                state.get("version") != 1
                or state.get("organization_id") != organization_id
                or state.get("state") not in {"pending", "acknowledged"}
            ):
                raise ValueError("invalid personal recovery state")
            self.repository.put_profile(
                _PERSONAL_RECOVERY_PROFILE,
                {
                    "version": 1,
                    "state": "acknowledged",
                    "organization_id": organization_id,
                    "acknowledged_at": datetime.now(
                        timezone.utc
                    ).isoformat(),
                },
            )
            return context | {"recovery_acknowledged": True}

    @staticmethod
    def _canonical_uuid(value: str, field: str) -> str:
        try:
            parsed = uuid.UUID(str(value))
        except (ValueError, AttributeError, TypeError):
            raise ValueError(f"{field} must be a canonical UUID") from None
        canonical = str(parsed)
        if canonical != str(value):
            raise ValueError(f"{field} must be a canonical UUID")
        return canonical

    @staticmethod
    def _base64url(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

    @staticmethod
    def _decode_base64url(value: str) -> bytes:
        raw = str(value or "")
        if not raw or not re.fullmatch(r"[A-Za-z0-9_-]+", raw):
            raise ValueError("invalid base64url value")
        return base64.urlsafe_b64decode(raw + ("=" * (-len(raw) % 4)))

    def _load_device_private_key(
        self,
        organization_id: str,
        device_id: str,
    ) -> bytes:
        row = self.repository.get_local_secret(
            organization_id,
            "device_private_key",
            device_id,
            0,
        )
        if row is None:
            raise PermissionDenied(
                "device private key is not unlocked on this device"
            )
        private_key = decrypt_local_secret(
            self._master_key,
            row["nonce"],
            row["ciphertext"],
            self._device_secret_aad(organization_id, device_id),
        )
        if len(private_key) != 32:
            raise PermissionDenied("invalid local device private key")
        return private_key

    def get_cloud_device_context(self, organization_id: str) -> dict | None:
        organization_id = self._canonical_uuid(
            organization_id, "organization_id"
        )
        return self.repository.get_profile(
            f"cloud_device_context:{organization_id}"
        )

    def prepare_cloud_device_registration(
        self,
        *,
        organization_id: str,
        user_id: str,
        role: str,
        membership_status: str,
        key_version: int,
        device_name: str,
    ) -> dict:
        """Create one local P-256 desktop identity for cloud membership."""
        organization_id = self._canonical_uuid(
            organization_id, "organization_id"
        )
        user_id = self._canonical_uuid(user_id, "user_id")
        role = str(role or "").lower()
        if role not in ROLES:
            raise ValueError("invalid cloud membership role")
        membership_status = str(membership_status or "").lower()
        if membership_status not in {"active", "invited"}:
            raise PermissionDenied("active or invited membership required")
        key_version = int(key_version)
        if key_version < 1:
            raise ValueError("invalid organization key version")
        device_name = str(device_name or "").strip()
        if not device_name or len(device_name) > 120:
            raise ValueError("device_name is required and must be at most 120 characters")

        with self._cloud_context_lock:
            existing = self.get_cloud_device_context(organization_id)
            if existing is not None:
                if (
                    existing.get("organization_id") != organization_id
                    or existing.get("user_id") != user_id
                    or existing.get("key_algorithm") != "p256"
                    or existing.get("device_kind") != "desktop"
                ):
                    raise PermissionDenied("cloud device context identity mismatch")
                device = self.repository.get_device(
                    str(existing.get("device_id") or "")
                )
                if (
                    device is None
                    or device["organization_id"] != organization_id
                    or device["user_id"] != user_id
                    or device.get("key_algorithm") != "p256"
                    or device.get("device_kind") != "desktop"
                    or bytes(device["public_key"])
                    != self._decode_base64url(
                        str(existing.get("device_public_key") or "")
                    )
                ):
                    raise PermissionDenied("cloud device context is invalid")
                self._load_device_private_key(
                    organization_id, str(existing["device_id"])
                )
                return existing

            device_id = str(uuid.uuid4())
            public_key, private_key = create_desktop_credential_keypair()
            private_nonce, private_ciphertext = encrypt_local_secret(
                self._master_key,
                private_key,
                self._device_secret_aad(organization_id, device_id),
            )
            context = {
                "organization_id": organization_id,
                "user_id": user_id,
                "device_id": device_id,
                "key_algorithm": "p256",
                "device_kind": "desktop",
                "status": "pending",
                "remote_key_version": key_version,
                "device_public_key": self._base64url(public_key),
                # The invited client cannot decrypt organization metadata yet.
                # These random authenticated-looking bytes reveal no device name.
                "device_name_ciphertext": self._base64url(os.urandom(32)),
                "device_name_nonce": self._base64url(os.urandom(12)),
            }
            return self.repository.create_cloud_device_context(
                context=context,
                organization_name=f"云端组织 {organization_id[:8]}",
                role=role,
                membership_status=membership_status,
                public_key=public_key,
                private_key_nonce=private_nonce,
                private_key_ciphertext=private_ciphertext,
            )

    def bind_personal_cloud_context(
        self,
        personal_context: dict,
        cloud_user_id: str,
    ) -> dict:
        """Bind a remote JWT identity without rewriting the personal profile."""
        organization_id = self._canonical_uuid(
            str(personal_context.get("organization_id") or ""),
            "organization_id",
        )
        cloud_user_id = self._canonical_uuid(cloud_user_id, "user_id")
        device_id = self._canonical_uuid(
            str(personal_context.get("device_id") or ""), "device_id"
        )
        personal = self.get_personal_context()
        if (
            personal is None
            or personal.get("organization_id") != organization_id
            or personal.get("device_id") != device_id
        ):
            raise PermissionDenied("local personal context mismatch")
        organization = self.repository.get_organization(organization_id)
        device = self.repository.get_device(device_id)
        if (
            organization is None
            or device is None
            or device["organization_id"] != organization_id
            or device["status"] != "active"
            or device.get("key_algorithm") != "p256"
            or device.get("device_kind") != "desktop"
        ):
            raise PermissionDenied(
                "active personal P-256 desktop device required"
            )
        key_version = int(organization["key_version"])
        self._load_org_key(organization_id, key_version)
        self._load_device_private_key(organization_id, device_id)
        context = {
            "organization_id": organization_id,
            "user_id": cloud_user_id,
            "device_id": device_id,
            "key_algorithm": "p256",
            "device_kind": "desktop",
            "status": "active",
            "key_version": key_version,
            "device_public_key": self._base64url(bytes(device["public_key"])),
        }
        return self.repository.bind_active_cloud_context(
            context,
            role="owner",
        )

    def activate_cloud_device_context(
        self,
        context: dict,
        *,
        remote_device: dict,
        envelope: dict,
        expected_key_version: int,
        role: str | None = None,
    ) -> dict:
        """Open a strictly bound envelope, then activate the local context."""
        organization_id = self._canonical_uuid(
            str(context.get("organization_id") or ""), "organization_id"
        )
        user_id = self._canonical_uuid(
            str(context.get("user_id") or ""), "user_id"
        )
        device_id = self._canonical_uuid(
            str(context.get("device_id") or ""), "device_id"
        )
        if (
            remote_device.get("organization_id") != organization_id
            or remote_device.get("id") != device_id
            or remote_device.get("user_id") != user_id
            or remote_device.get("key_algorithm") != "p256"
            or remote_device.get("device_kind") != "desktop"
            or remote_device.get("status") != "active"
            or not isinstance(remote_device.get("public_key"), (bytes, bytearray))
            or bytes(remote_device["public_key"])
            != self._decode_base64url(str(context["device_public_key"]))
        ):
            raise PermissionDenied("remote cloud device identity mismatch")
        key_version = int(envelope.get("key_version") or 0)
        if (
            envelope.get("organization_id") != organization_id
            or envelope.get("device_id") != device_id
            or envelope.get("key_algorithm") != "p256"
            or key_version != int(expected_key_version)
        ):
            raise PermissionDenied("organization key envelope binding mismatch")
        private_key = self._load_device_private_key(
            organization_id, device_id
        )
        try:
            org_key = open_org_key_for_p256(
                load_desktop_credential_private_key(private_key),
                {
                    "organization_id": organization_id,
                    "device_id": device_id,
                    "key_version": key_version,
                    "key_algorithm": "p256",
                    "ephemeral_public_key": envelope["ephemeral_public_key"],
                    "nonce": envelope["nonce"],
                    "ciphertext": envelope["ciphertext"],
                },
            )
        except (InvalidTag, KeyError, ValueError) as error:
            raise ValueError(
                "organization key envelope authentication failed"
            ) from error
        if len(org_key) != 32:
            raise ValueError("invalid organization key envelope")
        effective_role = str(role or "").lower()
        if effective_role and effective_role not in ROLES:
            raise ValueError("invalid cloud membership role")
        with self._cloud_context_lock:
            existing_secret = self.repository.get_local_secret(
                organization_id,
                "org_key",
                organization_id,
                key_version,
            )
            encrypted_secret = None
            if existing_secret is not None:
                if self._load_org_key(organization_id, key_version) != org_key:
                    raise PermissionDenied("organization key mismatch")
            else:
                encrypted_secret = encrypt_local_secret(
                    self._master_key,
                    org_key,
                    self._org_secret_aad(organization_id, key_version),
                )
            return self.repository.activate_cloud_device_context(
                context,
                key_version=key_version,
                role=effective_role or None,
                org_key_secret=encrypted_secret,
            )

    def refresh_cloud_membership(
        self,
        context: dict,
        *,
        cloud_user_id: str,
        role: str,
    ) -> None:
        """Apply the current remote role to an already-active local context."""
        cloud_user_id = self._canonical_uuid(cloud_user_id, "user_id")
        role = str(role or "").lower()
        if role not in ROLES:
            raise ValueError("invalid cloud membership role")
        if (
            context.get("user_id") != cloud_user_id
            or context.get("status") != "active"
        ):
            raise PermissionDenied("active cloud device context required")
        self.repository.refresh_cloud_membership(context, role=role)

    def resolve_cloud_context(
        self,
        organization_id: str,
        cloud_user_id: str,
    ) -> dict:
        """Return only a fully unlocked cloud context bound to current JWT."""
        organization_id = self._canonical_uuid(
            organization_id, "organization_id"
        )
        cloud_user_id = self._canonical_uuid(cloud_user_id, "user_id")
        context = self.get_cloud_device_context(organization_id)
        if (
            context is None
            or context.get("organization_id") != organization_id
            or context.get("user_id") != cloud_user_id
            or context.get("key_algorithm") != "p256"
            or context.get("device_kind") != "desktop"
            or context.get("status") != "active"
        ):
            raise PermissionDenied("active cloud device context required")
        device = self.repository.get_device(str(context.get("device_id") or ""))
        membership = self.repository.get_membership(
            organization_id, cloud_user_id
        )
        if (
            device is None
            or device["organization_id"] != organization_id
            or device["user_id"] not in {cloud_user_id, "local-owner"}
            or device["status"] != "active"
            or device.get("key_algorithm") != "p256"
            or device.get("device_kind") != "desktop"
            or membership is None
            or membership["status"] != "active"
            or bytes(device["public_key"])
            != self._decode_base64url(
                str(context.get("device_public_key") or "")
            )
        ):
            raise PermissionDenied("active cloud device context required")
        key_version = int(context.get("key_version") or 0)
        self._load_device_private_key(
            organization_id, str(context["device_id"])
        )
        self._load_org_key(organization_id, key_version)
        return context

    def prepare_cloud_bootstrap_context(
        self,
        personal_context: dict,
        cloud_user_id: str,
    ) -> dict:
        """Create a distinct P-256 cloud identity for a local organization."""
        organization_id = self._canonical_uuid(
            str(personal_context.get("organization_id") or ""),
            "organization_id",
        )
        personal = self.get_personal_context()
        if (
            personal is None
            or personal.get("organization_id") != organization_id
            or personal.get("device_id")
            != personal_context.get("device_id")
        ):
            raise PermissionDenied("local personal context mismatch")
        organization = self.repository.get_organization(organization_id)
        if organization is None:
            raise NotFound(organization_id)
        key_version = int(organization["key_version"])
        self._load_org_key(organization_id, key_version)
        return self.prepare_cloud_device_registration(
            organization_id=organization_id,
            user_id=self._canonical_uuid(cloud_user_id, "user_id"),
            role="owner",
            membership_status="active",
            key_version=key_version,
            device_name="Cloud desktop",
        )

    def _mvp_owner_session_binding(
        self,
        organization_id: str,
        user_id: str,
        device_id: str,
        session_id: str,
        key_version: int,
    ) -> str:
        message = (
            "v9:mvp-owner-session:1:"
            f"{organization_id}:{user_id}:{device_id}:{session_id}:"
            f"{key_version}"
        ).encode("ascii")
        return hmac.new(self._master_key, message, hashlib.sha256).hexdigest()

    def _authenticated_cloud_session_ids(self, authenticated_session) -> tuple[str, str]:
        try:
            access_token = str(authenticated_session.access_token() or "")
            token_parts = access_token.split(".")
            if (
                len(access_token) > 16384
                or len(token_parts) != 3
                or not re.fullmatch(r"[A-Za-z0-9_-]+", token_parts[1])
            ):
                raise ValueError("invalid JWT")
            claims = json.loads(
                self._decode_base64url(token_parts[1]).decode("utf-8")
            )
            if not isinstance(claims, dict):
                raise ValueError("invalid JWT claims")
            token_user_id = self._canonical_uuid(
                str(claims.get("sub") or ""), "token_user_id"
            )
            user_id = self._canonical_uuid(
                str(authenticated_session.user_id() or ""), "user_id"
            )
            session_id = self._canonical_uuid(
                str(claims.get("session_id") or ""), "session_id"
            )
        except (
            AttributeError,
            TypeError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ):
            raise PermissionDenied(
                "authenticated cloud session identity required"
            ) from None
        if token_user_id != user_id:
            raise PermissionDenied("authenticated session identity mismatch")
        return user_id, session_id

    def can_activate_bootstrapped_cloud_context(
        self,
        context: dict,
        *,
        authenticated_session,
        membership: dict,
        expected_key_version: int,
    ) -> bool:
        """Return whether the exact one-time Owner manifest binding is current."""
        try:
            organization_id = self._canonical_uuid(
                str(context.get("organization_id") or ""), "organization_id"
            )
            user_id, session_id = self._authenticated_cloud_session_ids(
                authenticated_session
            )
            key_version = int(expected_key_version)
            personal = self.get_personal_context()
            stored = self.get_cloud_device_context(organization_id)
            marker = context.get("mvp_owner_bootstrap")
            return bool(
                stored == context
                and context.get("status") == "pending"
                and context.get("user_id") == user_id
                and context.get("key_algorithm") == "p256"
                and context.get("device_kind") == "desktop"
                and isinstance(marker, dict)
                and marker.get("schema_version") == 1
                and marker.get("organization_id") == organization_id
                and marker.get("owner_user_id") == user_id
                and marker.get("device_id") == context.get("device_id")
                and marker.get("key_version") == key_version
                and hmac.compare_digest(
                    str(marker.get("session_binding") or ""),
                    self._mvp_owner_session_binding(
                        organization_id,
                        user_id,
                        str(context.get("device_id") or ""),
                        session_id,
                        key_version,
                    ),
                )
                and membership.get("organization_id") == organization_id
                and membership.get("user_id") == user_id
                and membership.get("role") == "owner"
                and membership.get("status") == "active"
                and int(context.get("remote_key_version") or 0) == key_version
                and personal is not None
                and personal.get("organization_id") == organization_id
                and not self.personal_recovery_pending()
                and int(
                    self.repository.get_organization(organization_id)[
                        "key_version"
                    ]
                ) == key_version
            )
        except (KeyError, PermissionDenied, TypeError, ValueError):
            return False

    def build_bootstrapped_cloud_key_envelope(
        self,
        context: dict,
        *,
        remote_device: dict,
        expected_key_version: int,
        membership: dict,
        authenticated_session,
    ) -> dict:
        """Seal the org key only for the exact first-Owner remote identity."""
        if not self.can_activate_bootstrapped_cloud_context(
            context,
            authenticated_session=authenticated_session,
            membership=membership,
            expected_key_version=expected_key_version,
        ):
            raise PermissionDenied("MVP Owner bootstrap binding mismatch")
        organization_id = str(context.get("organization_id") or "")
        device_id = str(context.get("device_id") or "")
        device = self.repository.get_device(device_id)
        organization = self.repository.get_organization(organization_id)
        if (
            organization is None
            or device is None
            or device.get("organization_id") != organization_id
            or device.get("key_algorithm") != "p256"
            or device.get("device_kind") != "desktop"
            or device.get("status") != "pending"
            or remote_device.get("id") != device_id
            or remote_device.get("organization_id") != organization_id
            or remote_device.get("user_id") != context.get("user_id")
            or remote_device.get("key_algorithm") != "p256"
            or remote_device.get("device_kind") != "desktop"
            or remote_device.get("status") != "active"
            or not isinstance(
                remote_device.get("public_key"), (bytes, bytearray)
            )
            or bytes(remote_device["public_key"])
            != bytes(device["public_key"])
        ):
            raise PermissionDenied("pending cloud P-256 device required")
        key_version = int(expected_key_version)
        return seal_org_key_for_p256(
            self._load_org_key(organization_id, key_version),
            bytes(device["public_key"]),
            org_id=organization_id,
            device_id=device_id,
            key_version=key_version,
        )

    def activate_bootstrapped_cloud_context(
        self,
        context: dict,
        *,
        remote_device: dict,
        envelope: dict,
        expected_key_version: int,
        membership: dict,
        authenticated_session,
    ) -> dict:
        """Activate an uploaded first-Owner envelope, then consume its marker."""
        if not self.can_activate_bootstrapped_cloud_context(
            context,
            authenticated_session=authenticated_session,
            membership=membership,
            expected_key_version=expected_key_version,
        ):
            raise PermissionDenied("MVP Owner bootstrap binding mismatch")
        active = self.activate_cloud_device_context(
            context,
            remote_device=remote_device,
            envelope=envelope,
            expected_key_version=int(expected_key_version),
            role="owner",
        )
        cleaned = dict(active)
        cleaned.pop("mvp_owner_bootstrap", None)
        with self._cloud_context_lock:
            stored = self.get_cloud_device_context(
                str(context.get("organization_id") or "")
            )
            if stored != active:
                raise PermissionDenied("activated cloud context changed")
            self.repository.put_profile(
                f"cloud_device_context:{context['organization_id']}",
                cleaned,
            )
        return cleaned

    def _cloud_ai_device(self, context: dict, cloud_user_id: str) -> dict:
        active = self.resolve_cloud_context(
            str(context.get("organization_id") or ""), cloud_user_id
        )
        if active.get("device_id") != context.get("device_id"):
            raise PermissionDenied("cloud device context mismatch")
        device = self.repository.get_device(str(active["device_id"]))
        if (
            device is None
            or device.get("user_id") != cloud_user_id
            or device.get("status") != "active"
            or device.get("key_algorithm") != "p256"
            or device.get("device_kind") != "desktop"
            or len(bytes(device["public_key"])) != 65
        ):
            raise PermissionDenied("active desktop P-256 device required")
        return {
            "id": str(device["id"]),
            "user_id": cloud_user_id,
            "status": "active",
            "device_kind": "desktop",
            "key_algorithm": "p256",
            "public_key": bytes(device["public_key"]),
        }

    def encrypt_cloud_ai_credential(
        self,
        context: dict,
        *,
        cloud_user_id: str,
        api_key: str,
        provider: str,
        model_id: str,
        credential_version: int,
        devices: list[dict],
    ) -> EncryptedAiCredential:
        """Encrypt a BYOK secret after validating the local cloud identity."""
        current = self._cloud_ai_device(context, cloud_user_id)
        if not any(
            str(item.get("id") or item.get("device_id") or "")
            == current["id"]
            for item in devices
            if isinstance(item, dict)
        ):
            raise PermissionDenied("current desktop device is not eligible")
        return encrypt_api_credential(
            api_key,
            user_id=cloud_user_id,
            provider=provider,
            model_id=model_id,
            credential_version=credential_version,
            devices=devices,
        )

    def open_cloud_ai_credential(
        self,
        context: dict,
        encrypted: EncryptedAiCredential | dict,
        *,
        cloud_user_id: str,
    ) -> InMemoryAiCredential:
        """Return one clearable in-memory credential for a trusted caller."""
        device = self._cloud_ai_device(context, cloud_user_id)
        private_key = self._load_device_private_key(
            str(context["organization_id"]), str(context["device_id"])
        )
        return decrypt_api_credential(
            encrypted,
            user_id=cloud_user_id,
            device=device,
            device_private_key=private_key,
        )

    def rewrap_cloud_ai_credential(
        self,
        context: dict,
        encrypted: EncryptedAiCredential | dict,
        *,
        cloud_user_id: str,
        target_device: dict,
    ):
        """Add one same-version P-256 envelope without opening the API key."""
        source_device = self._cloud_ai_device(context, cloud_user_id)
        private_key = self._load_device_private_key(
            str(context["organization_id"]), str(context["device_id"])
        )
        return rewrap_credential_for_new_device(
            encrypted,
            user_id=cloud_user_id,
            source_device=source_device,
            source_private_key=private_key,
            target_device=target_device,
        )

    def import_cloud_device_metadata(
        self,
        context: dict,
        remote_devices: list[dict],
    ) -> None:
        organization_id = str(context["organization_id"])
        for remote in remote_devices:
            device_id = self._canonical_uuid(
                str(remote.get("device_id") or remote.get("id") or ""),
                "device_id",
            )
            raw_user_id = remote.get("user_id")
            user_id = (
                self._canonical_uuid(str(raw_user_id), "device_user_id")
                if raw_user_id
                else None
            )
            public_key = remote.get("public_key")
            algorithm = str(remote.get("key_algorithm") or "")
            raw_device_kind = remote.get("device_kind")
            device_kind = (
                str(raw_device_kind or "").strip().lower()
                if raw_device_kind is not None
                else None
            )
            status = str(remote.get("status") or "active")
            if (
                (
                    remote.get("organization_id")
                    or remote.get("org_id")
                ) != organization_id
                or not isinstance(public_key, (bytes, bytearray))
                or algorithm not in {"x25519", "p256"}
                or len(public_key) != (32 if algorithm == "x25519" else 65)
                or device_kind not in {None, "desktop", "browser"}
                or status not in {"active", "revoked"}
            ):
                raise PermissionDenied("invalid remote device metadata")
            if device_id == str(context["device_id"]):
                local_device = self.repository.get_device(device_id)
                if (
                    local_device is None
                    or local_device["organization_id"] != organization_id
                    or local_device.get("key_algorithm") != "p256"
                    or local_device.get("device_kind") != "desktop"
                    or algorithm != "p256"
                    or device_kind not in {None, "desktop"}
                    or bytes(local_device["public_key"]) != bytes(public_key)
                    or status != "active"
                ):
                    raise PermissionDenied("local cloud device metadata mismatch")
                continue
            self.repository.upsert_cloud_device_metadata(
                organization_id=organization_id,
                device_id=device_id,
                user_id=user_id,
                public_key=bytes(public_key),
                key_algorithm=algorithm,
                device_kind=device_kind,
                status=status,
            )

    def build_cloud_bootstrap(self, context: dict) -> dict:
        """Build an ID-preserving, ciphertext-only Supabase bootstrap payload."""
        organization_id = str(context["organization_id"])
        device_id = str(context["device_id"])
        org = self.repository.get_organization(organization_id)
        device = self.repository.get_device(device_id)
        if (
            org is None
            or device is None
            or device["organization_id"] != organization_id
            or device["status"] not in {"pending", "active"}
            or device.get("key_algorithm") != "p256"
            or device.get("device_kind") != "desktop"
            or context.get("key_algorithm") != "p256"
            or context.get("device_kind") != "desktop"
            or context.get("device_public_key")
            != self._base64url(bytes(device["public_key"]))
        ):
            raise PermissionDenied(
                "local cloud desktop P-256 device required"
            )
        key_version = int(org["key_version"])
        org_key = self._load_org_key(organization_id, key_version)

        def encrypted_label(kind: str, value: str) -> tuple[str, str]:
            nonce = os.urandom(12)
            aad = (
                f"v9:metadata:1:{organization_id}:{kind}:{key_version}"
            ).encode("utf-8")
            ciphertext = AESGCM(org_key).encrypt(
                nonce,
                value.encode("utf-8"),
                aad,
            )
            def encode(raw: bytes) -> str:
                return base64.urlsafe_b64encode(raw).decode(
                    "ascii"
                ).rstrip("=")
            return encode(ciphertext), encode(nonce)

        name_ciphertext, name_nonce = encrypted_label(
            "organization-name", str(org["name"])
        )
        device_ciphertext, device_nonce = encrypted_label(
            f"device-name:{device_id}", str(device["name"])
        )
        return {
            "name_ciphertext": name_ciphertext,
            "name_nonce": name_nonce,
            "device_id": device_id,
            "device_public_key": base64.urlsafe_b64encode(
                bytes(device["public_key"])
            ).decode("ascii").rstrip("="),
            "device_name_ciphertext": device_ciphertext,
            "device_name_nonce": device_nonce,
            "key_algorithm": "p256",
            "requested_organization_id": organization_id,
        }

    def build_mvp_owner_bootstrap_manifest(
        self,
        personal_context: dict,
        *,
        authenticated_session,
    ) -> dict:
        """Build the one-time operator manifest from a validated cloud session."""
        owner_user_id, session_id = self._authenticated_cloud_session_ids(
            authenticated_session
        )
        if self.personal_recovery_pending():
            raise PermissionDenied(
                "personal recovery acknowledgement is required"
            )

        cloud_context = self.prepare_cloud_bootstrap_context(
            personal_context,
            owner_user_id,
        )
        bootstrap = self.build_cloud_bootstrap(cloud_context)
        if bootstrap.get("key_algorithm") != "p256":
            raise PermissionDenied("cloud desktop P-256 bootstrap required")
        manifest = {
            "schema_version": 1,
            "organization_id": bootstrap["requested_organization_id"],
            "owner_user_id": owner_user_id,
            "session_id": session_id,
            "name_ciphertext": bootstrap["name_ciphertext"],
            "name_nonce": bootstrap["name_nonce"],
            "device_id": bootstrap["device_id"],
            "device_public_key": bootstrap["device_public_key"],
            "device_name_ciphertext": bootstrap[
                "device_name_ciphertext"
            ],
            "device_name_nonce": bootstrap["device_name_nonce"],
            "key_algorithm": "p256",
            "device_kind": "desktop",
        }
        marker = {
            "schema_version": 1,
            "organization_id": cloud_context["organization_id"],
            "owner_user_id": owner_user_id,
            "device_id": cloud_context["device_id"],
            "key_version": int(cloud_context["remote_key_version"]),
            "session_binding": self._mvp_owner_session_binding(
                cloud_context["organization_id"],
                owner_user_id,
                cloud_context["device_id"],
                session_id,
                int(cloud_context["remote_key_version"]),
            ),
        }
        with self._cloud_context_lock:
            stored = self.get_cloud_device_context(
                cloud_context["organization_id"]
            )
            if stored != cloud_context:
                raise PermissionDenied("cloud bootstrap context changed")
            existing_marker = stored.get("mvp_owner_bootstrap")
            if existing_marker is not None and existing_marker != marker:
                raise PermissionDenied("cloud bootstrap session changed")
            marked_context = dict(stored)
            marked_context["mvp_owner_bootstrap"] = marker
            self.repository.put_profile(
                f"cloud_device_context:{cloud_context['organization_id']}",
                marked_context,
            )
        return manifest

    def build_cloud_device_pairing(
        self,
        context: dict,
        remote_device: dict,
    ) -> dict:
        organization_id = str(context["organization_id"])
        self._require(
            organization_id,
            str(context["user_id"]),
            "device.manage",
        )
        device_id = str(remote_device.get("id") or "")
        if remote_device.get("organization_id") != organization_id:
            raise PermissionDenied("cross-organization device pairing denied")
        if remote_device.get("status") != "pending":
            raise ValueError("device is not pending")
        key_algorithm = str(remote_device.get("key_algorithm") or "")
        device_kind = str(remote_device.get("device_kind") or "").lower()
        public_key = remote_device.get("public_key")
        if not isinstance(public_key, (bytes, bytearray)):
            raise ValueError("device public key must be bytes")
        if key_algorithm != "p256" or device_kind not in {
            "desktop",
            "browser",
        }:
            raise ValueError("pending cloud P-256 device required")
        org = self.repository.get_organization(organization_id)
        if org is None:
            raise NotFound(organization_id)
        key_version = int(org["key_version"])
        org_key = self._load_org_key(organization_id, key_version)
        envelope = seal_org_key_for_p256(
            org_key,
            bytes(public_key),
            org_id=organization_id,
            device_id=device_id,
            key_version=key_version,
        )
        return {
            "organization_id": organization_id,
            "device_id": device_id,
            "target_user_id": str(remote_device.get("user_id") or ""),
            "envelope_key_version": key_version,
            "envelope_algorithm": envelope["key_algorithm"],
            "ephemeral_public_key": envelope["ephemeral_public_key"],
            "envelope_nonce": envelope["nonce"],
            "envelope_ciphertext": envelope["ciphertext"],
        }

    def archive_news_evidence(self, context: dict, article: dict) -> dict:
        org_id = str(context["organization_id"])
        user_id = str(context["user_id"])
        device_id = str(context["device_id"])
        external_ref = str(article.get("aid") or "").strip()
        if not external_ref:
            link = str(article.get("link") or "").strip()
            if not link:
                raise ValueError("article aid or link is required")
            external_ref = hashlib.sha256(link.encode()).hexdigest()
        with self._evidence_archive_lock:
            existing = self.repository.get_record_ref(
                org_id, "news", external_ref
            )
            if existing:
                return {"record_id": existing, "created": False}
            content = {
                "title": str(article.get("title") or "无标题"),
                "summary": str(article.get("summary") or ""),
                "source": str(article.get("source") or "未知来源"),
                "published_at": str(article.get("date") or ""),
                "region": str(article.get("region") or ""),
                "priority": article.get("priority") or {},
                "annotations": [],
                "citation_status": "unreviewed",
                "provenance": {
                    "kind": "rss_news",
                    "source": str(article.get("source") or "未知来源"),
                    "url": str(article.get("link") or ""),
                    "article_id": external_ref,
                    "archived_at": datetime.now(timezone.utc).isoformat(),
                },
            }
            record = self.create_record(
                org_id, user_id, device_id, "evidence", content
            )
            self.repository.put_record_ref(
                org_id, "news", external_ref, record["record_id"]
            )
            return {"record_id": record["record_id"], "created": True}

    def list_evidence(self, context: dict) -> list[dict]:
        org_id = str(context["organization_id"])
        user_id = str(context["user_id"])
        self._require(org_id, user_id, "record.read")
        result = []
        for row in self.repository.list_records_by_type(org_id, "evidence"):
            envelope = RecordEnvelope.from_mapping(row)
            result.append(
                {
                    "record_id": envelope.record_id,
                    "version": envelope.version,
                    "content_hash": envelope.content_hash,
                    "updated_at": row["updated_at"],
                    "content": decrypt_record(
                        self._load_org_key(org_id, envelope.key_version),
                        envelope,
                    ),
                }
            )
        return result

    def save_alert_rule(self, context: dict, value: dict) -> dict:
        content = normalize_alert_rule(value)
        record_id = str(value.get("record_id") or "").strip()
        if record_id:
            return self.update_record(
                str(context["organization_id"]),
                str(context["user_id"]),
                str(context["device_id"]),
                record_id,
                expected_version=int(value.get("version") or 0),
                content=content,
            )
        return self.create_record(
            str(context["organization_id"]),
            str(context["user_id"]),
            str(context["device_id"]),
            "alert_rule",
            content,
        )

    def list_alert_rules(self, context: dict) -> list[dict]:
        org_id = str(context["organization_id"])
        user_id = str(context["user_id"])
        self._require(org_id, user_id, "record.read")
        result = []
        for row in self.repository.list_records_by_type(org_id, "alert_rule"):
            envelope = RecordEnvelope.from_mapping(row)
            result.append(
                {
                    "record_id": envelope.record_id,
                    "version": envelope.version,
                    "content_hash": envelope.content_hash,
                    "updated_at": row["updated_at"],
                    "content": decrypt_record(
                        self._load_org_key(org_id, envelope.key_version),
                        envelope,
                    ),
                }
            )
        return result

    def _list_decrypted_records(
        self, context: dict, record_type: str
    ) -> list[dict]:
        org_id = str(context["organization_id"])
        self._require(org_id, str(context["user_id"]), "record.read")
        result = []
        for row in self.repository.list_records_by_type(org_id, record_type):
            envelope = RecordEnvelope.from_mapping(row)
            result.append(
                {
                    "record_id": envelope.record_id,
                    "record_type": envelope.record_type,
                    "version": envelope.version,
                    "content_hash": envelope.content_hash,
                    "updated_at": row["updated_at"],
                    "content": decrypt_record(
                        self._load_org_key(org_id, envelope.key_version),
                        envelope,
                    ),
                }
            )
        return result

    def _verify_record_ids(
        self, context: dict, record_ids: list[str], expected_type: str
    ) -> None:
        for record_id in record_ids:
            record = self.read_record(
                str(context["organization_id"]),
                str(context["user_id"]),
                record_id,
            )
            if record["record_type"] != expected_type or record["deleted"]:
                raise ValueError(f"{expected_type} 记录无效：{record_id}")

    def _verify_case_references(self, context: dict, content: dict) -> None:
        self._verify_record_ids(context, content["evidence_ids"], "evidence")
        self._verify_record_ids(
            context,
            content.get("contradictory_evidence_ids", []),
            "evidence",
        )
        for conclusion in content["conclusions"]:
            self._verify_record_ids(
                context, conclusion["evidence_ids"], "evidence"
            )
            self._verify_record_ids(
                context,
                conclusion.get("counter_evidence_ids", []),
                "evidence",
            )
            self._verify_record_ids(
                context, conclusion.get("claim_ids", []), "claim"
            )

    @staticmethod
    def _bind_case_calibration_context(
        changes: dict, actor_id: str
    ) -> dict:
        bound = copy.deepcopy(changes)
        timestamp = datetime.now(timezone.utc).isoformat()
        conclusions = bound.get("conclusions")
        if not isinstance(conclusions, list):
            return bound
        for conclusion in conclusions:
            if not isinstance(conclusion, dict):
                continue
            calibration = conclusion.get("human_calibration")
            if isinstance(calibration, dict):
                calibration["actor"] = actor_id
                calibration["time"] = timestamp
            confidence_inputs = conclusion.get("confidence_inputs")
            if not isinstance(confidence_inputs, dict):
                continue
            calibration = confidence_inputs.get("human_calibration")
            if isinstance(calibration, dict):
                calibration["actor"] = actor_id
                calibration["time"] = timestamp
        return bound

    def _verify_document_references(
        self, context: dict, content: dict
    ) -> None:
        self._verify_record_ids(
            context, evidence_ids_for_document(content), "evidence"
        )
        claim_ids = [
            claim_id
            for paragraph in content.get("paragraphs", [])
            if isinstance(paragraph, dict)
            for claim_id in paragraph.get("claim_ids", [])
        ]
        self._verify_record_ids(
            context, list(dict.fromkeys(claim_ids)), "claim"
        )

    def create_claim(self, context: dict, value: dict) -> dict:
        content = normalize_claim(value)
        self._verify_record_ids(context, content["evidence_ids"], "evidence")
        self._verify_record_ids(
            context, content["counter_evidence_ids"], "evidence"
        )
        return self.create_record(
            str(context["organization_id"]),
            str(context["user_id"]),
            str(context["device_id"]),
            "claim",
            content,
        )

    def list_claims(self, context: dict) -> list[dict]:
        return self._list_decrypted_records(context, "claim")

    def create_graph_entity(self, context: dict, value: dict) -> dict:
        content = normalize_entity(value)
        self._verify_record_ids(context, content["evidence_ids"], "evidence")
        return self.create_record(
            str(context["organization_id"]),
            str(context["user_id"]),
            str(context["device_id"]),
            "entity",
            content,
        )

    def create_graph_relation(self, context: dict, value: dict) -> dict:
        content = normalize_relation(value)
        self._verify_record_ids(context, content["evidence_ids"], "evidence")
        for field in ("subject_id", "object_id"):
            record = self.read_record(
                str(context["organization_id"]),
                str(context["user_id"]),
                content[field],
            )
            if record["record_type"] != "entity" or record["deleted"]:
                raise ValueError(f"{field} 必须引用实体")
        return self.create_record(
            str(context["organization_id"]),
            str(context["user_id"]),
            str(context["device_id"]),
            "relation",
            content,
        )

    def get_graph(self, context: dict) -> dict:
        return {
            "entities": self._list_decrypted_records(context, "entity"),
            "relations": self._list_decrypted_records(context, "relation"),
        }

    def create_geo_event(self, context: dict, value: dict) -> dict:
        content = normalize_geo_event(value)
        self._verify_record_ids(context, content["evidence_ids"], "evidence")
        self._verify_record_ids(context, content["entity_ids"], "entity")
        for field, record_type in (("alert_id", "alert"), ("case_id", "case")):
            if content[field]:
                self._verify_record_ids(
                    context, [content[field]], record_type
                )
        return self.create_record(
            str(context["organization_id"]),
            str(context["user_id"]),
            str(context["device_id"]),
            "geo_event",
            content,
        )

    def list_geo_events(self, context: dict, hours: int = 120) -> list[dict]:
        cutoff = datetime.now(timezone.utc).timestamp() - max(
            1, min(int(hours), 8760)
        ) * 3600
        result = []
        for item in self._list_decrypted_records(context, "geo_event"):
            try:
                occurred = datetime.fromisoformat(
                    str(item["content"].get("occurred_at") or "").replace(
                        "Z", "+00:00"
                    )
                )
                if occurred.tzinfo is None:
                    occurred = occurred.replace(tzinfo=timezone.utc)
                if occurred.timestamp() < cutoff:
                    continue
            except ValueError:
                continue
            result.append(item)
        return result

    def materialize_rule_hits(
        self, context: dict, rules: list[dict], articles: list[dict]
    ) -> dict:
        evaluation = evaluate_alert_rules(rules, articles)
        article_index = {
            str(article.get("aid") or article.get("link") or ""): article
            for article in articles
        }
        created = []
        with self._workflow_lock:
            for hit in evaluation["hits"]:
                external_ref = f"{hit.get('rule_id')}:{hit['article_id']}"
                if self.repository.get_record_ref(
                    str(context["organization_id"]), "alert_hit", external_ref
                ):
                    continue
                article = article_index.get(hit["article_id"])
                if article is None:
                    continue
                evidence = self.archive_news_evidence(context, article)
                content = {
                    "title": hit["title"],
                    "status": "new",
                    "severity": hit["severity"],
                    "rule_id": hit.get("rule_id"),
                    "rule_name": hit["rule_name"],
                    "article_id": hit["article_id"],
                    "source": hit["source"],
                    "published_at": hit["published_at"],
                    "matched_keywords": hit["matched_keywords"],
                    "evidence_ids": [evidence["record_id"]],
                    "claimed_by": None,
                    "snoozed_until": None,
                    "case_id": None,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
                record = self.create_record(
                    str(context["organization_id"]),
                    str(context["user_id"]),
                    str(context["device_id"]),
                    "alert",
                    content,
                )
                self.repository.put_record_ref(
                    str(context["organization_id"]),
                    "alert_hit",
                    external_ref,
                    record["record_id"],
                )
                created.append(record["record_id"])
        return {
            "created": len(created),
            "record_ids": created,
            "total_hits": evaluation["total_hits"],
        }

    def list_alerts(self, context: dict) -> list[dict]:
        return self._list_decrypted_records(context, "alert")

    def list_cases(self, context: dict) -> list[dict]:
        return self._list_decrypted_records(context, "case")

    def triage_alert(
        self,
        context: dict,
        record_id: str,
        *,
        action: str,
        expected_version: int,
        value: dict | None = None,
    ) -> dict:
        action = str(action or "").strip().lower()
        if action not in ALERT_ACTIONS:
            raise ValueError("无效告警动作")
        value = value or {}
        with self._workflow_lock:
            alert_record = self.read_record(
                str(context["organization_id"]),
                str(context["user_id"]),
                record_id,
            )
            if alert_record["record_type"] != "alert":
                raise ValueError("目标不是告警记录")
            if int(alert_record["version"]) != int(expected_version):
                raise VersionConflict(
                    f"expected {expected_version}, "
                    f"current {alert_record['version']}"
                )
            content = dict(alert_record["content"])
            case_id = None
            if action == "claim":
                content["status"] = "triaged"
                content["claimed_by"] = str(context["user_id"])
            elif action == "snooze":
                content["status"] = "snoozed"
                content["snoozed_until"] = str(value.get("until") or "")
            elif action == "escalate":
                content["status"] = "escalated"
                content["severity"] = "critical"
            elif action == "close":
                content["status"] = "closed"
                content["resolution"] = str(value.get("resolution") or "")
            else:
                existing = self.repository.get_record_ref(
                    str(context["organization_id"]), "alert_case", record_id
                )
                if existing:
                    case_id = existing
                else:
                    case = self.create_record(
                        str(context["organization_id"]),
                        str(context["user_id"]),
                        str(context["device_id"]),
                        "case",
                        new_case_from_alert(record_id, content),
                    )
                    case_id = case["record_id"]
                    self.repository.put_record_ref(
                        str(context["organization_id"]),
                        "alert_case",
                        record_id,
                        case_id,
                    )
                content["status"] = "converted"
                content["case_id"] = case_id
            updated = self.update_record(
                str(context["organization_id"]),
                str(context["user_id"]),
                str(context["device_id"]),
                record_id,
                expected_version=expected_version,
                content=content,
            )
            return {**updated, "case_id": case_id}

    def update_case(
        self,
        context: dict,
        record_id: str,
        *,
        expected_version: int,
        changes: dict,
    ) -> dict:
        current = self.read_record(
            str(context["organization_id"]),
            str(context["user_id"]),
            record_id,
        )
        if current["record_type"] != "case":
            raise ValueError("目标不是案件记录")
        bound_changes = self._bind_case_calibration_context(
            changes, str(context["user_id"])
        )
        content = apply_case_changes(current["content"], bound_changes)
        self._verify_case_references(context, content)
        return self.update_record(
            str(context["organization_id"]),
            str(context["user_id"]),
            str(context["device_id"]),
            record_id,
            expected_version=expected_version,
            content=content,
        )

    def create_agent_job(self, context: dict, value: dict) -> dict:
        content = new_agent_job(value)
        self._verify_record_ids(context, content["evidence_ids"], "evidence")
        return self.create_record(
            str(context["organization_id"]),
            str(context["user_id"]),
            str(context["device_id"]),
            "job",
            content,
        )

    def list_agent_jobs(self, context: dict) -> list[dict]:
        return self._list_decrypted_records(context, "job")

    def control_agent_job(
        self,
        context: dict,
        record_id: str,
        *,
        action: str,
        expected_version: int,
        value: dict | None = None,
    ) -> dict:
        current = self.read_record(
            str(context["organization_id"]),
            str(context["user_id"]),
            record_id,
        )
        if current["record_type"] != "job" or current["deleted"]:
            raise ValueError("目标不是有效智能体任务")
        if int(current["version"]) != int(expected_version):
            raise VersionConflict(
                f"expected {expected_version}, current {current['version']}"
            )
        content, transition = transition_agent_job(
            current["content"], action, value
        )
        self._verify_record_ids(context, content["evidence_ids"], "evidence")
        updated = self.update_record(
            str(context["organization_id"]),
            str(context["user_id"]),
            str(context["device_id"]),
            record_id,
            expected_version=expected_version,
            content=content,
        )
        return {**updated, "transition": transition}

    def execute_agent_job_phase(
        self,
        context: dict,
        record_id: str,
        *,
        expected_version: int,
        executor,
    ) -> dict:
        current = self.read_record(
            str(context["organization_id"]),
            str(context["user_id"]),
            record_id,
        )
        if current["record_type"] != "job" or current["deleted"]:
            raise ValueError("目标不是有效智能体任务")
        if int(current["version"]) != int(expected_version):
            raise VersionConflict(
                f"expected {expected_version}, current {current['version']}"
            )
        if current["content"].get("state") != "running":
            raise ValueError("只有运行中任务可以在本机执行阶段")
        evidence = []
        for evidence_id in current["content"]["evidence_ids"]:
            record = self.read_record(
                str(context["organization_id"]),
                str(context["user_id"]),
                evidence_id,
            )
            if record["record_type"] != "evidence" or record["deleted"]:
                raise ValueError(f"evidence 记录无效：{evidence_id}")
            evidence.append(
                {
                    "record_id": evidence_id,
                    "content": record["content"],
                }
            )
        try:
            output = str(
                executor(
                    {
                        "job": current["content"],
                        "evidence": evidence,
                        "execution_scope": "unlocked_desktop_only",
                    }
                )
                or ""
            ).strip()
            if not output:
                raise ValueError("本地 AI 阶段输出为空")
            content, transition = transition_agent_job(
                current["content"], "advance", {"output": output}
            )
            execution_error = None
        except Exception as error:
            name = type(error).__name__.lower()
            message = str(error)[:1000] or type(error).__name__
            if "timeout" in name or "timeout" in message.lower():
                error_type = "ai_timeout"
            elif "connection" in name or "network" in message.lower():
                error_type = "network_error"
            else:
                error_type = "ai_rejected"
            content, transition = transition_agent_job(
                current["content"],
                "fail",
                {"error_type": error_type, "message": message},
            )
            execution_error = content["error"]
        updated = self.update_record(
            str(context["organization_id"]),
            str(context["user_id"]),
            str(context["device_id"]),
            record_id,
            expected_version=expected_version,
            content=content,
        )
        return {
            **updated,
            "transition": transition,
            "execution_error": execution_error,
        }

    def create_scenario(self, context: dict, value: dict) -> dict:
        content = new_scenario(value)
        self._verify_scenario_evidence(context, content)
        return self.create_record(
            str(context["organization_id"]),
            str(context["user_id"]),
            str(context["device_id"]),
            "scenario",
            content,
        )

    def list_scenarios(self, context: dict) -> list[dict]:
        return self._list_decrypted_records(context, "scenario")

    def _verify_scenario_evidence(
        self, context: dict, content: dict
    ) -> None:
        evidence_ids = list(content["evidence_ids"])
        for branch in content["branches"].values():
            evidence_ids.extend(branch["counter_evidence_ids"])
        for output in content["team_outputs"].values():
            evidence_ids.extend(output["evidence_ids"])
        self._verify_record_ids(
            context, list(dict.fromkeys(evidence_ids)), "evidence"
        )

    def update_scenario(
        self,
        context: dict,
        record_id: str,
        *,
        expected_version: int,
        changes: dict,
    ) -> dict:
        current = self.read_record(
            str(context["organization_id"]),
            str(context["user_id"]),
            record_id,
        )
        if current["record_type"] != "scenario" or current["deleted"]:
            raise ValueError("目标不是有效情景推演")
        content = apply_scenario_changes(current["content"], changes)
        self._verify_scenario_evidence(context, content)
        return self.update_record(
            str(context["organization_id"]),
            str(context["user_id"]),
            str(context["device_id"]),
            record_id,
            expected_version=expected_version,
            content=content,
        )

    def _record_with_hash(
        self, context: dict, record_id: str, expected_type: str
    ) -> dict:
        record = self.read_record(
            str(context["organization_id"]),
            str(context["user_id"]),
            record_id,
        )
        if record["record_type"] != expected_type or record["deleted"]:
            raise ValueError(f"目标不是有效 {expected_type} 记录")
        raw = self.repository.get_record(record_id)
        return {
            **record,
            "content_hash": str(raw["content_hash"]),
            "updated_at": str(raw["updated_at"]),
        }

    def create_document(self, context: dict, value: dict) -> dict:
        content = new_document(value)
        self._verify_document_references(context, content)
        return self.create_record(
            str(context["organization_id"]),
            str(context["user_id"]),
            str(context["device_id"]),
            "document",
            content,
        )

    def list_documents(self, context: dict) -> list[dict]:
        return self._list_decrypted_records(context, "document")

    def update_document(
        self,
        context: dict,
        record_id: str,
        *,
        expected_version: int,
        changes: dict,
    ) -> dict:
        current = self._record_with_hash(context, record_id, "document")
        content = apply_document_changes(current["content"], changes)
        self._verify_document_references(context, content)
        return self.update_record(
            str(context["organization_id"]),
            str(context["user_id"]),
            str(context["device_id"]),
            record_id,
            expected_version=expected_version,
            content=content,
        )

    def _source_index(self, context: dict, document_content: dict) -> list[dict]:
        records = [
            self._record_with_hash(context, record_id, "evidence")
            for record_id in evidence_ids_for_document(document_content)
        ]
        return build_source_index(document_content, records)

    def export_document(
        self, context: dict, record_id: str, output_format: str
    ) -> tuple[bytes, str]:
        document = self._record_with_hash(context, record_id, "document")
        source_index = self._source_index(context, document["content"])
        output_format = str(output_format or "").lower()
        if output_format == "docx":
            return (
                build_document_docx(document["content"], source_index),
                safe_filename(document["content"]["title"], "docx"),
            )
        if output_format == "pdf":
            return (
                build_document_pdf(document["content"], source_index),
                safe_filename(document["content"]["title"], "pdf"),
            )
        raise ValueError("仅支持 docx 或 pdf")

    def _create_audit_event(
        self,
        context: dict,
        *,
        action: str,
        target_id: str,
        details: dict | None = None,
    ) -> dict:
        return self.create_record(
            str(context["organization_id"]),
            str(context["user_id"]),
            str(context["device_id"]),
            "audit_event",
            {
                "action": action,
                "target_id": target_id,
                "actor_user_id": str(context["user_id"]),
                "occurred_at": datetime.now(timezone.utc).isoformat(),
                "details": details or {},
            },
            _workflow=True,
        )

    def create_publication_item(
        self, context: dict, document_id: str
    ) -> dict:
        self._require(
            str(context["organization_id"]),
            str(context["user_id"]),
            "layout.edit",
        )
        document = self._record_with_hash(context, document_id, "document")
        created = self.create_record(
            str(context["organization_id"]),
            str(context["user_id"]),
            str(context["device_id"]),
            "publication_item",
            new_publication_item(document, str(context["user_id"])),
            _workflow=True,
        )
        self._create_audit_event(
            context,
            action="publication.created",
            target_id=created["record_id"],
            details={"document_id": document_id},
        )
        return created

    def list_publication_items(self, context: dict) -> list[dict]:
        return self._list_decrypted_records(context, "publication_item")

    def move_publication_item(
        self,
        context: dict,
        record_id: str,
        *,
        expected_version: int,
        status: str,
        position: int = 0,
    ) -> dict:
        self._require(
            str(context["organization_id"]),
            str(context["user_id"]),
            "layout.edit",
        )
        status = str(status or "").strip().lower()
        if status not in BOARD_STATUSES - {"signed", "recalled"}:
            raise ValueError("无效版面状态")
        publication = self._record_with_hash(
            context, record_id, "publication_item"
        )
        current = publication["content"]
        if current.get("status") in {"signed", "recalled"}:
            raise PermissionDenied("已签发或撤回版面不可由编辑移动")
        document = self._record_with_hash(
            context, str(current.get("document_id")), "document"
        )
        if (
            status == "pending_approval"
            and not validate_document(document["content"]).get("ready")
        ):
            raise ValueError("稿件校验未通过，不能进入待签发")
        content = dict(current)
        content.update(
            {
                "status": status,
                "position": max(0, int(position or 0)),
                "title": document["content"]["title"],
                "document_version": document["version"],
                "document_content_hash": document["content_hash"],
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        updated = self.update_record(
            str(context["organization_id"]),
            str(context["user_id"]),
            str(context["device_id"]),
            record_id,
            expected_version=expected_version,
            content=content,
            _workflow=True,
        )
        self._create_audit_event(
            context,
            action="publication.moved",
            target_id=record_id,
            details={"from": current.get("status"), "to": status},
        )
        return {**updated, "status": status}

    def sign_publication_item(
        self,
        context: dict,
        record_id: str,
        *,
        expected_version: int,
    ) -> dict:
        self._require(
            str(context["organization_id"]),
            str(context["user_id"]),
            "publication.approve",
        )
        publication = self._record_with_hash(
            context, record_id, "publication_item"
        )
        document = self._record_with_hash(
            context,
            str(publication["content"].get("document_id")),
            "document",
        )
        source_index = self._source_index(context, document["content"])
        content = signed_publication_content(
            publication["content"],
            document,
            source_index,
            str(context["user_id"]),
        )
        updated = self.update_record(
            str(context["organization_id"]),
            str(context["user_id"]),
            str(context["device_id"]),
            record_id,
            expected_version=expected_version,
            content=content,
            _workflow=True,
            _permission="publication.approve",
        )
        self._create_audit_event(
            context,
            action="publication.signed",
            target_id=record_id,
            details=content["signed_snapshot"]["receipt"],
        )
        return {**updated, "status": "signed"}

    def recall_publication_item(
        self,
        context: dict,
        record_id: str,
        *,
        expected_version: int,
        reason: str,
    ) -> dict:
        self._require(
            str(context["organization_id"]),
            str(context["user_id"]),
            "publication.recall",
        )
        reason = str(reason or "").strip()
        if not reason:
            raise ValueError("撤回原因必填")
        publication = self._record_with_hash(
            context, record_id, "publication_item"
        )
        content = dict(publication["content"])
        if content.get("status") != "signed":
            raise ValueError("只有已签发稿件可以撤回")
        content.update(
            {
                "status": "recalled",
                "recalled_at": datetime.now(timezone.utc).isoformat(),
                "recalled_by": str(context["user_id"]),
                "recall_reason": reason[:2000],
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        updated = self.update_record(
            str(context["organization_id"]),
            str(context["user_id"]),
            str(context["device_id"]),
            record_id,
            expected_version=expected_version,
            content=content,
            _workflow=True,
            _permission="publication.recall",
        )
        self._create_audit_event(
            context,
            action="publication.recalled",
            target_id=record_id,
            details={"reason": reason[:2000]},
        )
        return {**updated, "status": "recalled"}

    def list_audit_events(self, context: dict) -> list[dict]:
        self._require(
            str(context["organization_id"]),
            str(context["user_id"]),
            "audit.read",
        )
        return list(reversed(self._list_decrypted_records(context, "audit_event")))

    def export_publication(
        self, context: dict, record_id: str, output_format: str
    ) -> tuple[bytes, str]:
        publication = self._record_with_hash(
            context, record_id, "publication_item"
        )
        snapshot = publication["content"].get("signed_snapshot")
        if not snapshot:
            raise ValueError("版面尚未生成签发快照")
        document_content = snapshot["document"]
        source_index = snapshot["source_index"]
        output_format = str(output_format or "").lower()
        if output_format == "docx":
            return (
                build_document_docx(document_content, source_index),
                safe_filename(document_content["title"], "docx"),
            )
        if output_format == "pdf":
            return (
                build_document_pdf(document_content, source_index),
                safe_filename(document_content["title"], "pdf"),
            )
        raise ValueError("仅支持 docx 或 pdf")

    def authorize(self, org_id: str, user_id: str, permission: str) -> bool:
        membership = self.repository.get_membership(org_id, user_id)
        return bool(
            membership and role_allows(membership["role"], permission)
        )

    def add_member(
        self,
        organization_id: str,
        acting_user_id: str,
        member_user_id: str,
        role: str,
    ) -> dict:
        self._require(organization_id, acting_user_id, "member.manage")
        role = (role or "").lower()
        if role not in ROLES:
            raise ValueError("invalid role")
        acting = self.repository.get_membership(
            organization_id, acting_user_id
        )
        if role == "owner" and acting["role"] != "owner":
            raise PermissionDenied("only an owner can grant owner role")
        self.repository.add_membership(
            organization_id, member_user_id, role
        )
        return {
            "organization_id": organization_id,
            "user_id": member_user_id,
            "role": role,
        }

    def _require(self, org_id: str, user_id: str, permission: str) -> None:
        if not self.authorize(org_id, user_id, permission):
            raise PermissionDenied(f"{permission} denied")

    @staticmethod
    def _validate_type(record_type: str) -> str:
        record_type = (record_type or "").strip().lower()
        if record_type not in RECORD_TYPES:
            raise InvalidRecordType(record_type)
        return record_type

    def create_record(
        self,
        organization_id: str,
        user_id: str,
        device_id: str,
        record_type: str,
        content: Any,
        *,
        _workflow: bool = False,
    ) -> dict:
        record_type = self._validate_type(record_type)
        if record_type in _WORKFLOW_RECORD_TYPES and not _workflow:
            raise PermissionDenied(
                f"{record_type} 只能由受控工作流创建"
            )
        self._require(
            organization_id, user_id, _CREATE_PERMISSIONS[record_type]
        )
        device = self.repository.get_device(device_id)
        if (
            not device
            or device["organization_id"] != organization_id
            or device["status"] != "active"
        ):
            raise PermissionDenied("active organization device required")
        org = self.repository.get_organization(organization_id)
        if not org:
            raise NotFound(organization_id)
        record_id = str(uuid.uuid4())
        key_version = int(org["key_version"])
        org_key = self._load_org_key(organization_id, key_version)
        envelope = encrypt_record(
            org_key=org_key,
            org_id=organization_id,
            record_id=record_id,
            record_type=record_type,
            version=1,
            key_version=key_version,
            content=content,
        )
        self.repository.put_record(envelope, device_id)
        return {
            "record_id": record_id,
            "record_type": record_type,
            "version": 1,
            "content_hash": envelope.content_hash,
        }

    def read_record(
        self, organization_id: str, user_id: str, record_id: str
    ) -> dict:
        self._require(organization_id, user_id, "record.read")
        row = self.repository.get_record(record_id)
        if row is None:
            raise NotFound(record_id)
        if row["organization_id"] != organization_id:
            raise PermissionDenied("cross-organization record access denied")
        envelope = RecordEnvelope.from_mapping(row)
        org_key = self._load_org_key(organization_id, envelope.key_version)
        return {
            "record_id": record_id,
            "record_type": envelope.record_type,
            "version": envelope.version,
            "deleted": bool(row["deleted"]),
            "content": decrypt_record(org_key, envelope),
        }

    def update_record(
        self,
        organization_id: str,
        user_id: str,
        device_id: str,
        record_id: str,
        *,
        expected_version: int,
        content: Any,
        _workflow: bool = False,
        _permission: str | None = None,
    ) -> dict:
        current = self.repository.get_record(record_id)
        if current is None:
            raise NotFound(record_id)
        if current["organization_id"] != organization_id:
            raise PermissionDenied("cross-organization record access denied")
        record_type = self._validate_type(current["record_type"])
        self._require(
            organization_id,
            user_id,
            _permission or _CREATE_PERMISSIONS[record_type],
        )
        current_key = self._load_org_key(
            organization_id, int(current["key_version"])
        )
        current_content = decrypt_record(
            current_key, RecordEnvelope.from_mapping(current)
        )
        if (
            record_type == "publication_item"
            and current_content.get("status") == "signed"
            and not _workflow
        ):
            raise PermissionDenied("已签发版面不可覆盖")
        if record_type in _WORKFLOW_RECORD_TYPES and not _workflow:
            raise PermissionDenied(
                f"{record_type} 只能由受控工作流更新"
            )
        org = self.repository.get_organization(organization_id)
        key_version = int(org["key_version"])
        org_key = self._load_org_key(organization_id, key_version)
        proposed_version = int(expected_version) + 1
        candidate = encrypt_record(
            org_key=org_key,
            org_id=organization_id,
            record_id=record_id,
            record_type=record_type,
            version=proposed_version,
            key_version=key_version,
            content=content,
        )
        if int(current["version"]) != int(expected_version):
            self.repository.put_conflict(
                organization_id,
                record_id,
                "stale_write",
                RecordEnvelope.from_mapping(current).to_dict(),
                candidate.to_dict(),
            )
            raise VersionConflict(
                f"expected {expected_version}, current {current['version']}"
            )
        self.repository.put_record(candidate, device_id)
        return {
            "record_id": record_id,
            "version": proposed_version,
            "content_hash": candidate.content_hash,
        }

    def add_device(
        self,
        organization_id: str,
        acting_user_id: str,
        device_user_id: str,
        device_name: str,
    ) -> dict:
        self._require(organization_id, acting_user_id, "device.manage")
        if not self.repository.get_membership(
            organization_id, device_user_id
        ):
            raise PermissionDenied("device user must be an active member")
        org = self.repository.get_organization(organization_id)
        if not org:
            raise NotFound(organization_id)
        device_id = str(uuid.uuid4())
        public_key, private_key = create_device_keypair()
        self.repository.add_device(
            device_id,
            organization_id,
            device_user_id,
            device_name,
            public_key,
            key_algorithm="x25519",
            device_kind="desktop",
        )
        self._store_device_private_key(
            organization_id, device_id, private_key
        )
        key_version = int(org["key_version"])
        org_key = self._load_org_key(organization_id, key_version)
        envelope = seal_org_key_for_device(
            org_key,
            public_key,
            org_id=organization_id,
            device_id=device_id,
            key_version=key_version,
        )
        self.repository.put_key_envelope(envelope)
        return {"device_id": device_id, "key_version": key_version}

    def pair_device(
        self,
        organization_id: str,
        acting_user_id: str,
        device_user_id: str,
        device_name: str,
        device_public_key: bytes,
    ) -> dict:
        """Register a remote public key; the private key never leaves that device."""
        self._require(organization_id, acting_user_id, "device.manage")
        if not self.repository.get_membership(
            organization_id, device_user_id
        ):
            raise PermissionDenied("device user must be an active member")
        org = self.repository.get_organization(organization_id)
        if not org:
            raise NotFound(organization_id)
        device_id = str(uuid.uuid4())
        self.repository.add_device(
            device_id,
            organization_id,
            device_user_id,
            device_name,
            device_public_key,
            key_algorithm="x25519",
            device_kind="desktop",
        )
        key_version = int(org["key_version"])
        org_key = self._load_org_key(organization_id, key_version)
        envelope = seal_org_key_for_device(
            org_key,
            device_public_key,
            org_id=organization_id,
            device_id=device_id,
            key_version=key_version,
        )
        self.repository.put_key_envelope(envelope)
        return {
            "device_id": device_id,
            "key_version": key_version,
            "key_envelope": envelope,
        }

    def create_pairing_session(
        self,
        context: dict,
        *,
        target_user_id: str,
        device_name: str,
        ttl_seconds: int = 300,
    ) -> dict:
        organization_id = str(context.get("organization_id") or "")
        acting_user_id = str(context.get("user_id") or "")
        self._require(organization_id, acting_user_id, "device.manage")
        if not self.repository.get_membership(
            organization_id, target_user_id
        ):
            raise PermissionDenied("device user must be an active member")
        device_name = str(device_name or "").strip()
        if not device_name or len(device_name) > 120:
            raise ValueError("device_name is required and must be at most 120 characters")
        ttl_seconds = int(ttl_seconds)
        if ttl_seconds < 60 or ttl_seconds > 600:
            raise ValueError("pairing code lifetime must be between 60 and 600 seconds")
        pairing_code = secrets.token_urlsafe(32)
        code_hash = hashlib.sha256(pairing_code.encode()).hexdigest()
        session_id = str(uuid.uuid4())
        expires_at = (
            datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        ).isoformat()
        self.repository.create_pairing_session(
            session_id,
            organization_id,
            acting_user_id,
            str(target_user_id),
            device_name,
            code_hash,
            expires_at,
        )
        return {
            "session_id": session_id,
            "pairing_code": pairing_code,
            "expires_at": expires_at,
        }

    def claim_pairing_session(
        self, pairing_code: str, device_public_key: bytes
    ) -> dict:
        pairing_code = str(pairing_code or "")
        if len(pairing_code) < 32:
            raise ValueError("配对码无效或已使用")
        if len(device_public_key) != 32:
            raise ValueError("X25519 public key must be 32 bytes")
        code_hash = hashlib.sha256(pairing_code.encode()).hexdigest()
        session = self.repository.consume_pairing_session(code_hash)
        if session is None:
            raise ValueError("配对码无效、已过期或已使用")
        return self.pair_device(
            session["organization_id"],
            session["acting_user_id"],
            session["target_user_id"],
            session["device_name"],
            device_public_key,
        )

    def recover_device(
        self,
        organization_id: str,
        user_id: str,
        device_name: str,
        recovery_code: str,
    ) -> dict:
        membership = self.repository.get_membership(organization_id, user_id)
        if not membership:
            raise PermissionDenied("active membership required")
        org = self.repository.get_organization(organization_id)
        if not org:
            raise NotFound(organization_id)
        key_version = int(org["key_version"])
        recovery_envelope = self.repository.get_recovery_envelope(
            organization_id, key_version
        )
        if recovery_envelope is None:
            raise NotFound("recovery envelope")
        org_key = recover_org_key(recovery_code, recovery_envelope)
        self._store_org_key(organization_id, key_version, org_key)
        device_id = str(uuid.uuid4())
        public_key, private_key = create_device_keypair()
        self.repository.add_device(
            device_id,
            organization_id,
            user_id,
            device_name,
            public_key,
            key_algorithm="x25519",
            device_kind="desktop",
        )
        self._store_device_private_key(
            organization_id, device_id, private_key
        )
        envelope = seal_org_key_for_device(
            org_key,
            public_key,
            org_id=organization_id,
            device_id=device_id,
            key_version=key_version,
        )
        self.repository.put_key_envelope(envelope)
        return {"device_id": device_id, "key_version": key_version}

    def export_outbox(self, organization_id: str) -> list[dict]:
        """Return cloud-safe events containing encrypted payloads only."""
        events = []
        for row in self.repository.list_outbox(organization_id):
            events.append(
                {
                    "event_id": row["event_id"],
                    "organization_id": row["organization_id"],
                    "record_id": row["record_id"],
                    "operation": row["operation"],
                    "payload": row["payload"],
                }
            )
        return events

    def queue_initial_snapshot(
        self, organization_id: str, user_id: str
    ) -> dict[str, int]:
        """Explicitly stage existing ciphertext for an empty Supabase project."""
        self._require(organization_id, user_id, "system.configure")
        return self.repository.queue_initial_snapshot(organization_id)

    def prepare_initial_snapshot_import(
        self, organization_id: str, user_id: str
    ) -> dict:
        """Build the remote import manifest from ciphertext metadata only."""
        self._require(organization_id, user_id, "system.configure")
        return self.repository.build_initial_snapshot_manifest(organization_id)

    def begin_initial_snapshot_import(
        self, organization_id: str, user_id: str, manifest: dict
    ) -> dict:
        self._require(organization_id, user_id, "system.configure")
        return self.repository.begin_initial_snapshot_session(
            organization_id,
            expected_count=int(manifest["expected_count"]),
            manifest_hash=str(manifest["manifest_hash"]),
        )

    def abort_initial_snapshot_import(
        self, organization_id: str, user_id: str, manifest_hash: str
    ) -> None:
        self._require(organization_id, user_id, "system.configure")
        self.repository.abort_initial_snapshot_session(
            organization_id, manifest_hash
        )

    def finish_initial_snapshot_import(
        self, organization_id: str, user_id: str, manifest_hash: str
    ) -> None:
        self._require(organization_id, user_id, "system.configure")
        self.repository.complete_initial_snapshot_session(
            organization_id, manifest_hash
        )

    def prepare_initial_snapshot_completion(
        self, organization_id: str, user_id: str
    ) -> dict:
        """Fail closed until every snapshot event is locally acknowledged."""
        self._require(organization_id, user_id, "system.configure")
        status = self.repository.get_initial_snapshot_completion(
            organization_id
        )
        if not status["ready"]:
            raise ValueError(
                "initial snapshot completion blocked by pending, retry, "
                "manual, conflict, or missing snapshot event"
            )
        return status

    def validate_local_conflict_resolution_event(
        self,
        organization_id: str,
        user_id: str,
        event: dict,
    ) -> None:
        """Bind a remote resolution to the exact current local ciphertext."""
        self._require(organization_id, user_id, "record.read")
        event = validate_ciphertext_event(event)
        payload = event["payload"]
        envelope = RecordEnvelope.from_mapping(payload)
        if envelope.org_id != organization_id:
            raise PermissionDenied("cross-organization resolution denied")
        try:
            org_key = self._load_org_key(
                organization_id, envelope.key_version
            )
            decrypt_record(org_key, envelope)
        except (InvalidTag, UnicodeDecodeError) as error:
            raise ValueError(
                "conflict resolution ciphertext authentication failed"
            ) from error
        current = self.repository.get_record(envelope.record_id)
        if current is None:
            raise NotFound(envelope.record_id)
        local_envelope = RecordEnvelope.from_mapping(current)
        if (
            local_envelope != envelope
            or str(current["device_id"]) != str(payload["device_id"])
            or bool(current["deleted"]) != bool(payload.get("deleted"))
        ):
            raise ValueError(
                "conflict resolution event does not match local head"
            )

    def list_conflicts(
        self, organization_id: str, user_id: str
    ) -> list[dict]:
        self._require(organization_id, user_id, "record.read")
        return self.repository.list_conflicts(organization_id)

    def build_encrypted_payload(
        self,
        organization_id: str,
        device_id: str,
        record_id: str,
        record_type: str,
        version: int,
        content: Any,
    ) -> dict:
        """Build a client ciphertext payload for sync/import adapters."""
        record_type = self._validate_type(record_type)
        org = self.repository.get_organization(organization_id)
        if not org:
            raise NotFound(organization_id)
        key_version = int(org["key_version"])
        envelope = encrypt_record(
            org_key=self._load_org_key(organization_id, key_version),
            org_id=organization_id,
            record_id=record_id,
            record_type=record_type,
            version=version,
            key_version=key_version,
            content=content,
        )
        return envelope.to_dict() | {
            "device_id": device_id,
            "deleted": False,
            "version_id": str(uuid.uuid4()),
            "base_version_id": None,
        }

    def apply_remote_event(
        self,
        organization_id: str,
        user_id: str,
        event: dict,
        *,
        remote_cursor: int | None,
    ) -> dict:
        self._require(organization_id, user_id, "record.read")
        if event.get("organization_id") != organization_id:
            raise PermissionDenied("cross-organization sync event denied")
        event_id = str(event.get("event_id") or "")
        if not event_id:
            raise ValueError("event_id is required")
        if self.repository.has_sync_event(event_id):
            return {"state": "duplicate", "event_id": event_id}
        event = validate_ciphertext_event(event)
        payload = event["payload"]
        try:
            envelope = RecordEnvelope.from_mapping(payload)
        except (KeyError, TypeError, ValueError) as error:
            raise UntrustedSyncEvent(
                "invalid_ciphertext_structure"
            ) from error
        if envelope.org_id != organization_id:
            raise PermissionDenied("payload organization mismatch")
        org_key = self._load_org_key(organization_id, envelope.key_version)
        try:
            decrypt_record(org_key, envelope)
        except InvalidTag as error:
            raise UntrustedSyncEvent(
                "ciphertext_authentication_failed"
            ) from error
        except ValueError as error:
            raise UntrustedSyncEvent(
                "content_integrity_failed"
            ) from error
        current = self.repository.get_record(envelope.record_id)
        if event.get("applied") is False:
            local_payload = (
                RecordEnvelope.from_mapping(current).to_dict()
                if current is not None
                else {
                    "record_id": envelope.record_id,
                    "state": "missing_local_head",
                }
            )
            conflict_id = self.repository.put_conflict(
                organization_id,
                envelope.record_id,
                "cloud_preserved_branch",
                local_payload,
                dict(payload),
            )
            self.repository.record_sync_event(
                event_id, organization_id, remote_cursor
            )
            return {
                "state": "conflict",
                "event_id": event_id,
                "conflict_id": conflict_id,
            }
        if current is None:
            self.repository.put_record(
                envelope,
                str(payload["device_id"]),
                deleted=bool(payload.get("deleted")),
                enqueue=False,
                version_id=str(payload["version_id"]),
                base_version_id=payload.get("base_version_id"),
            )
            self.repository.record_sync_event(
                event_id, organization_id, remote_cursor
            )
            return {"state": "applied", "event_id": event_id}

        local_envelope = RecordEnvelope.from_mapping(current)
        if (
            envelope.version == local_envelope.version
            and envelope.content_hash == local_envelope.content_hash
        ):
            self.repository.record_sync_event(
                event_id, organization_id, remote_cursor
            )
            return {"state": "duplicate", "event_id": event_id}

        pending_local = self.repository.has_pending_outbox(envelope.record_id)
        if envelope.version <= local_envelope.version or pending_local:
            reason = (
                "stale_remote"
                if envelope.version <= local_envelope.version
                else "concurrent_body_edit"
            )
            conflict_id = self.repository.put_conflict(
                organization_id,
                envelope.record_id,
                reason,
                local_envelope.to_dict(),
                envelope.to_dict(),
            )
            self.repository.record_sync_event(
                event_id, organization_id, remote_cursor
            )
            return {
                "state": "conflict",
                "event_id": event_id,
                "conflict_id": conflict_id,
            }

        self.repository.put_record(
            envelope,
            str(payload["device_id"]),
            deleted=bool(payload.get("deleted")),
            enqueue=False,
            version_id=str(payload["version_id"]),
            base_version_id=payload.get("base_version_id"),
        )
        self.repository.record_sync_event(
            event_id, organization_id, remote_cursor
        )
        return {"state": "applied", "event_id": event_id}

    def revoke_device(
        self, organization_id: str, acting_user_id: str, device_id: str
    ) -> dict:
        self._require(organization_id, acting_user_id, "device.manage")
        device = self.repository.get_device(device_id)
        if (
            not device
            or device["organization_id"] != organization_id
            or device["status"] != "active"
        ):
            raise NotFound(device_id)
        rotation = self._rotate_org_key(
            organization_id,
            excluded_device_ids={device_id},
            revoke_device_id=device_id,
        )
        return {
            "organization_id": organization_id,
            "revoked_device_id": device_id,
            **rotation,
        }

    def revoke_member(
        self,
        organization_id: str,
        acting_user_id: str,
        member_user_id: str,
    ) -> dict:
        self._require(organization_id, acting_user_id, "member.manage")
        target = self.repository.get_membership(
            organization_id, member_user_id
        )
        if not target:
            raise NotFound(member_user_id)
        if target["role"] == "owner":
            raise PermissionDenied("owner transfer is required before revocation")
        excluded = {
            row["id"]
            for row in self.repository.list_active_devices(organization_id)
            if row["user_id"] == member_user_id
        }
        rotation = self._rotate_org_key(
            organization_id,
            excluded_device_ids=excluded,
            revoke_user_id=member_user_id,
        )
        return {
            "organization_id": organization_id,
            "revoked_user_id": member_user_id,
            **rotation,
        }

    def _rotate_org_key(
        self,
        organization_id: str,
        *,
        excluded_device_ids: set[str],
        revoke_device_id: str | None = None,
        revoke_user_id: str | None = None,
    ) -> dict:
        if self.repository.has_active_initial_snapshot_session(
            organization_id
        ):
            raise ValueError(
                "key rotation is blocked during initial snapshot import"
            )
        org = self.repository.get_organization(organization_id)
        old_version = int(org["key_version"])
        new_version = old_version + 1
        old_key = self._load_org_key(organization_id, old_version)
        new_key = generate_org_key()
        rotated_records = []
        for row in self.repository.list_records(organization_id):
            envelope = RecordEnvelope.from_mapping(row)
            rotated = rewrap_record_data_key(
                old_key,
                new_key,
                envelope,
                new_key_version=new_version,
            )
            rotated_records.append(
                (rotated, row["device_id"], bool(row["deleted"]))
            )
        device_envelopes = []
        for row in self.repository.list_active_devices(organization_id):
            if row["id"] in excluded_device_ids:
                continue
            algorithm = row.get("key_algorithm")
            kind = row.get("device_kind")
            if algorithm == "p256" and kind in {"desktop", "browser"}:
                envelope = seal_org_key_for_p256(
                    new_key,
                    row["public_key"],
                    org_id=organization_id,
                    device_id=row["id"],
                    key_version=new_version,
                )
            elif algorithm == "x25519" and kind == "desktop":
                envelope = seal_org_key_for_device(
                    new_key,
                    row["public_key"],
                    org_id=organization_id,
                    device_id=row["id"],
                    key_version=new_version,
                )
            else:
                raise PermissionDenied(
                    "device key algorithm or kind is unknown; rotation denied"
                )
            device_envelopes.append(envelope)
        recovery_code, recovery_envelope = create_recovery_envelope(
            new_key, organization_id, key_version=new_version
        )
        # Store the new local secret first. If the subsequent SQLite transaction
        # fails, the organization remains on the old version and stays usable.
        self._store_org_key(organization_id, new_version, new_key)
        self.repository.apply_key_rotation(
            organization_id,
            new_version,
            rotated_records,
            device_envelopes,
            recovery_envelope,
            revoke_device_id=revoke_device_id,
            revoke_user_id=revoke_user_id,
        )
        return {
            "key_version": new_version,
            "recovery_code": recovery_code,
        }
