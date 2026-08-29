"""Client-side envelope encryption primitives used by the V9 desktop only."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass, replace
from typing import Any, Mapping

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


DPAPI_MASTER_KEY_MAGIC = b"DefenseTracker-V9-DPAPI\x00"
_RECORD_CONTENT_COMMITMENT_DOMAIN = (
    b"DefenseTracker-V9-record-ciphertext-commitment-v1\x00"
)
_BLOB_CONTENT_COMMITMENT_DOMAIN = (
    b"DefenseTracker-V9-blob-ciphertext-commitment-v1\x00"
)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _canonical_json(content: Any) -> bytes:
    return json.dumps(
        content,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _record_content_aad(
    org_id: str, record_id: str, record_type: str, version: int
) -> bytes:
    return (
        f"v9:record-content:1:{org_id}:{record_id}:{record_type}:{version}"
    ).encode("utf-8")


def _record_key_aad(
    org_id: str,
    record_id: str,
    record_type: str,
    version: int,
    key_version: int,
) -> bytes:
    return (
        f"v9:record-key:1:{org_id}:{record_id}:{record_type}:{version}:{key_version}"
    ).encode("utf-8")


def _record_content_commitment(
    *,
    org_id: str,
    record_id: str,
    record_type: str,
    version: int,
    nonce: bytes,
    ciphertext: bytes,
) -> str:
    """Commit to randomized ciphertext without fingerprinting its plaintext."""
    return hashlib.sha256(
        _RECORD_CONTENT_COMMITMENT_DOMAIN
        + _record_content_aad(org_id, record_id, record_type, version)
        + nonce
        + ciphertext
    ).hexdigest()


@dataclass(frozen=True)
class RecordEnvelope:
    org_id: str
    record_id: str
    record_type: str
    version: int
    key_version: int
    ciphertext: bytes
    nonce: bytes
    wrapped_data_key: bytes
    wrap_nonce: bytes
    content_hash: str

    def with_ciphertext(self, ciphertext: bytes) -> "RecordEnvelope":
        return replace(self, ciphertext=ciphertext)

    def to_dict(self) -> dict:
        return {
            "organization_id": self.org_id,
            "record_id": self.record_id,
            "record_type": self.record_type,
            "version": self.version,
            "key_version": self.key_version,
            "ciphertext": _b64(self.ciphertext),
            "nonce": _b64(self.nonce),
            "wrapped_data_key": _b64(self.wrapped_data_key),
            "wrap_nonce": _b64(self.wrap_nonce),
            "content_hash": self.content_hash,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RecordEnvelope":
        return cls(
            org_id=str(value.get("organization_id") or value.get("org_id")),
            record_id=str(value["record_id"]),
            record_type=str(value["record_type"]),
            version=int(value["version"]),
            key_version=int(value["key_version"]),
            ciphertext=_unb64(value["ciphertext"])
            if isinstance(value["ciphertext"], str)
            else bytes(value["ciphertext"]),
            nonce=_unb64(value["nonce"])
            if isinstance(value["nonce"], str)
            else bytes(value["nonce"]),
            wrapped_data_key=_unb64(value["wrapped_data_key"])
            if isinstance(value["wrapped_data_key"], str)
            else bytes(value["wrapped_data_key"]),
            wrap_nonce=_unb64(value["wrap_nonce"])
            if isinstance(value["wrap_nonce"], str)
            else bytes(value["wrap_nonce"]),
            content_hash=str(value["content_hash"]),
        )


@dataclass(frozen=True)
class BlobEnvelope:
    org_id: str
    object_id: str
    key_version: int
    ciphertext: bytes
    nonce: bytes
    wrapped_data_key: bytes
    wrap_nonce: bytes
    content_hash: str

    def to_dict(self) -> dict:
        return {
            "organization_id": self.org_id,
            "object_id": self.object_id,
            "key_version": self.key_version,
            "ciphertext": _b64(self.ciphertext),
            "nonce": _b64(self.nonce),
            "wrapped_data_key": _b64(self.wrapped_data_key),
            "wrap_nonce": _b64(self.wrap_nonce),
            "content_hash": self.content_hash,
        }


def generate_org_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def encrypt_record(
    *,
    org_key: bytes,
    org_id: str,
    record_id: str,
    record_type: str,
    version: int,
    key_version: int,
    content: Any,
) -> RecordEnvelope:
    plaintext = _canonical_json(content)
    data_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(data_key).encrypt(
        nonce,
        plaintext,
        _record_content_aad(org_id, record_id, record_type, version),
    )
    wrap_nonce = os.urandom(12)
    wrapped_data_key = AESGCM(org_key).encrypt(
        wrap_nonce,
        data_key,
        _record_key_aad(
            org_id, record_id, record_type, version, key_version
        ),
    )
    return RecordEnvelope(
        org_id=org_id,
        record_id=record_id,
        record_type=record_type,
        version=version,
        key_version=key_version,
        ciphertext=ciphertext,
        nonce=nonce,
        wrapped_data_key=wrapped_data_key,
        wrap_nonce=wrap_nonce,
        content_hash=_record_content_commitment(
            org_id=org_id,
            record_id=record_id,
            record_type=record_type,
            version=version,
            nonce=nonce,
            ciphertext=ciphertext,
        ),
    )


def _unwrap_data_key(org_key: bytes, envelope: RecordEnvelope) -> bytes:
    return AESGCM(org_key).decrypt(
        envelope.wrap_nonce,
        envelope.wrapped_data_key,
        _record_key_aad(
            envelope.org_id,
            envelope.record_id,
            envelope.record_type,
            envelope.version,
            envelope.key_version,
        ),
    )


def decrypt_record(org_key: bytes, envelope: RecordEnvelope) -> Any:
    data_key = _unwrap_data_key(org_key, envelope)
    plaintext = AESGCM(data_key).decrypt(
        envelope.nonce,
        envelope.ciphertext,
        _record_content_aad(
            envelope.org_id,
            envelope.record_id,
            envelope.record_type,
            envelope.version,
        ),
    )
    current_commitment = _record_content_commitment(
        org_id=envelope.org_id,
        record_id=envelope.record_id,
        record_type=envelope.record_type,
        version=envelope.version,
        nonce=envelope.nonce,
        ciphertext=envelope.ciphertext,
    )
    legacy_commitment = hashlib.sha256(plaintext).hexdigest()
    if not hmac.compare_digest(
        current_commitment, envelope.content_hash
    ) and not hmac.compare_digest(legacy_commitment, envelope.content_hash):
        raise ValueError("record content hash mismatch")
    return json.loads(plaintext.decode("utf-8"))


def rewrap_record_data_key(
    old_org_key: bytes,
    new_org_key: bytes,
    envelope: RecordEnvelope,
    *,
    new_key_version: int,
) -> RecordEnvelope:
    data_key = _unwrap_data_key(old_org_key, envelope)
    wrap_nonce = os.urandom(12)
    wrapped = AESGCM(new_org_key).encrypt(
        wrap_nonce,
        data_key,
        _record_key_aad(
            envelope.org_id,
            envelope.record_id,
            envelope.record_type,
            envelope.version,
            new_key_version,
        ),
    )
    return replace(
        envelope,
        key_version=new_key_version,
        wrapped_data_key=wrapped,
        wrap_nonce=wrap_nonce,
    )


def _blob_content_aad(org_id: str, object_id: str) -> bytes:
    return f"v9:blob-content:1:{org_id}:{object_id}".encode()


def _blob_content_commitment(
    *, org_id: str, object_id: str, nonce: bytes, ciphertext: bytes
) -> str:
    """Commit to randomized blob ciphertext without fingerprinting plaintext."""
    return hashlib.sha256(
        _BLOB_CONTENT_COMMITMENT_DOMAIN
        + _blob_content_aad(org_id, object_id)
        + nonce
        + ciphertext
    ).hexdigest()


def _blob_key_aad(org_id: str, object_id: str, key_version: int) -> bytes:
    return f"v9:blob-key:1:{org_id}:{object_id}:{key_version}".encode()


def encrypt_blob(
    org_key: bytes,
    *,
    org_id: str,
    object_id: str,
    key_version: int,
    plaintext: bytes,
) -> BlobEnvelope:
    data_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(data_key).encrypt(
        nonce, plaintext, _blob_content_aad(org_id, object_id)
    )
    wrap_nonce = os.urandom(12)
    wrapped_data_key = AESGCM(org_key).encrypt(
        wrap_nonce,
        data_key,
        _blob_key_aad(org_id, object_id, key_version),
    )
    return BlobEnvelope(
        org_id=org_id,
        object_id=object_id,
        key_version=key_version,
        ciphertext=ciphertext,
        nonce=nonce,
        wrapped_data_key=wrapped_data_key,
        wrap_nonce=wrap_nonce,
        content_hash=_blob_content_commitment(
            org_id=org_id,
            object_id=object_id,
            nonce=nonce,
            ciphertext=ciphertext,
        ),
    )


def decrypt_blob(org_key: bytes, envelope: BlobEnvelope) -> bytes:
    data_key = AESGCM(org_key).decrypt(
        envelope.wrap_nonce,
        envelope.wrapped_data_key,
        _blob_key_aad(
            envelope.org_id, envelope.object_id, envelope.key_version
        ),
    )
    plaintext = AESGCM(data_key).decrypt(
        envelope.nonce,
        envelope.ciphertext,
        _blob_content_aad(envelope.org_id, envelope.object_id),
    )
    current_commitment = _blob_content_commitment(
        org_id=envelope.org_id,
        object_id=envelope.object_id,
        nonce=envelope.nonce,
        ciphertext=envelope.ciphertext,
    )
    legacy_commitment = hashlib.sha256(plaintext).hexdigest()
    if not hmac.compare_digest(
        current_commitment, envelope.content_hash
    ) and not hmac.compare_digest(legacy_commitment, envelope.content_hash):
        raise ValueError("blob content hash mismatch")
    return plaintext


def create_device_keypair() -> tuple[bytes, bytes]:
    private = X25519PrivateKey.generate()
    public = private.public_key()
    return (
        public.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ),
        private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ),
    )


def _device_aad(org_id: str, device_id: str, key_version: int) -> bytes:
    return f"v9:device-envelope:1:{org_id}:{device_id}:{key_version}".encode()


def seal_org_key_for_device(
    org_key: bytes,
    device_public_key: bytes,
    *,
    org_id: str,
    device_id: str,
    key_version: int,
) -> dict:
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    target_public = X25519PublicKey.from_public_bytes(device_public_key)
    shared = ephemeral_private.exchange(target_public)
    aad = _device_aad(org_id, device_id, key_version)
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=aad,
    ).derive(shared)
    nonce = os.urandom(12)
    ciphertext = AESGCM(wrapping_key).encrypt(nonce, org_key, aad)
    return {
        "organization_id": org_id,
        "device_id": device_id,
        "key_version": key_version,
        "ephemeral_public_key": _b64(ephemeral_public),
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
    }


def open_org_key_for_device(device_private_key: bytes, envelope: Mapping) -> bytes:
    private = X25519PrivateKey.from_private_bytes(device_private_key)
    ephemeral = X25519PublicKey.from_public_bytes(
        _unb64(str(envelope["ephemeral_public_key"]))
    )
    org_id = str(envelope["organization_id"])
    device_id = str(envelope["device_id"])
    key_version = int(envelope["key_version"])
    aad = _device_aad(org_id, device_id, key_version)
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=aad,
    ).derive(private.exchange(ephemeral))
    return AESGCM(wrapping_key).decrypt(
        _unb64(str(envelope["nonce"])),
        _unb64(str(envelope["ciphertext"])),
        aad,
    )


def seal_org_key_for_p256(
    org_key: bytes,
    device_public_key: bytes,
    *,
    org_id: str,
    device_id: str,
    key_version: int,
) -> dict:
    target_public = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        device_public_key,
    )
    ephemeral_private = ec.generate_private_key(ec.SECP256R1())
    shared = ephemeral_private.exchange(ec.ECDH(), target_public)
    salt = (
        f"v9:org-envelope-salt:1:{org_id}:{device_id}:{key_version}"
    ).encode()
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"v9:org-envelope-kek:1",
    ).derive(shared)
    aad = (
        f"v9:org-envelope:1:{org_id}:{device_id}:{key_version}:p256"
    ).encode()
    nonce = os.urandom(12)
    ciphertext = AESGCM(wrapping_key).encrypt(nonce, org_key, aad)
    ephemeral_public = ephemeral_private.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    return {
        "organization_id": org_id,
        "device_id": device_id,
        "key_version": key_version,
        "key_algorithm": "p256",
        "ephemeral_public_key": _b64(ephemeral_public),
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
    }


def open_org_key_for_p256(
    device_private_key: ec.EllipticCurvePrivateKey,
    envelope: Mapping,
) -> bytes:
    ephemeral = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        _unb64(str(envelope["ephemeral_public_key"])),
    )
    org_id = str(envelope["organization_id"])
    device_id = str(envelope["device_id"])
    key_version = int(envelope["key_version"])
    shared = device_private_key.exchange(ec.ECDH(), ephemeral)
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=(
            f"v9:org-envelope-salt:1:{org_id}:{device_id}:{key_version}"
        ).encode(),
        info=b"v9:org-envelope-kek:1",
    ).derive(shared)
    aad = (
        f"v9:org-envelope:1:{org_id}:{device_id}:{key_version}:p256"
    ).encode()
    return AESGCM(wrapping_key).decrypt(
        _unb64(str(envelope["nonce"])),
        _unb64(str(envelope["ciphertext"])),
        aad,
    )


def create_recovery_envelope(
    org_key: bytes, org_id: str, *, key_version: int
) -> tuple[str, dict]:
    code_bytes = os.urandom(32)
    code = _b64(code_bytes)
    salt = os.urandom(16)
    aad = f"v9:recovery:1:{org_id}:{key_version}".encode()
    wrapping_key = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(
        code_bytes
    )
    nonce = os.urandom(12)
    envelope = {
        "organization_id": org_id,
        "key_version": key_version,
        "salt": _b64(salt),
        "nonce": _b64(nonce),
        "ciphertext": _b64(AESGCM(wrapping_key).encrypt(nonce, org_key, aad)),
    }
    return code, envelope


def recover_org_key(code: str, envelope: Mapping) -> bytes:
    code_bytes = _unb64(code)
    org_id = str(envelope["organization_id"])
    key_version = int(envelope["key_version"])
    salt = _unb64(str(envelope["salt"]))
    aad = f"v9:recovery:1:{org_id}:{key_version}".encode()
    wrapping_key = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(
        code_bytes
    )
    return AESGCM(wrapping_key).decrypt(
        _unb64(str(envelope["nonce"])),
        _unb64(str(envelope["ciphertext"])),
        aad,
    )


def encrypt_local_secret(master_key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    return nonce, AESGCM(master_key).encrypt(nonce, plaintext, aad)


def decrypt_local_secret(
    master_key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes
) -> bytes:
    return AESGCM(master_key).decrypt(nonce, ciphertext, aad)


def protect_local_master_key(master_key: bytes) -> bytes:
    """Protect the desktop master key for the current Windows user."""
    if len(master_key) != 32:
        raise ValueError("local V9 master key must be 32 bytes")
    from .supabase_client import WindowsDpapiProtector

    return DPAPI_MASTER_KEY_MAGIC + WindowsDpapiProtector().protect(master_key)


def unprotect_local_master_key(payload: bytes) -> bytes:
    """Open a versioned DPAPI master-key payload for the current Windows user."""
    if not payload.startswith(DPAPI_MASTER_KEY_MAGIC):
        raise ValueError("invalid local V9 master key format")
    protected = payload[len(DPAPI_MASTER_KEY_MAGIC):]
    if not protected:
        raise ValueError("invalid local V9 master key payload")
    from .supabase_client import WindowsDpapiProtector

    master_key = WindowsDpapiProtector().unprotect(protected)
    if len(master_key) != 32:
        raise ValueError("invalid local V9 master key")
    return master_key
