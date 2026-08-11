"""Desktop-only zero-knowledge storage for user AI API credentials."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid
from dataclasses import dataclass, replace
from typing import Iterable, Literal, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .ai_providers import REGISTRY_VERSION, resolve_provider


_CREDENTIAL_FORMAT = 1
_MAX_API_KEY_BYTES = 4096
_MAX_ENVELOPES = 32


class AiCredentialError(ValueError):
    """Base class for redacted credential failures."""


class CredentialDeviceError(AiCredentialError):
    pass


class CredentialAuthenticationError(AiCredentialError):
    pass


class CredentialClearedError(AiCredentialError):
    pass


def create_desktop_credential_keypair() -> tuple[bytes, bytes]:
    """Create a P-256 desktop keypair using raw 32-byte private storage."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    private_value = private_key.private_numbers().private_value.to_bytes(
        32, "big"
    )
    return public_key, private_value


def load_desktop_credential_private_key(
    value: bytes | bytearray | ec.EllipticCurvePrivateKey,
) -> ec.EllipticCurvePrivateKey:
    """Load a P-256 private key without accepting PEM or other key types."""
    if isinstance(value, ec.EllipticCurvePrivateKey):
        if value.curve.name != ec.SECP256R1().name:
            raise CredentialDeviceError("P-256 device private key required")
        return value
    if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
        raise CredentialDeviceError("P-256 device private key required")
    try:
        return ec.derive_private_key(
            int.from_bytes(value, "big"), ec.SECP256R1()
        )
    except ValueError as exc:
        raise CredentialDeviceError(
            "P-256 device private key required"
        ) from exc


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: object, *, maximum: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > maximum * 2:
        raise AiCredentialError("invalid encrypted credential payload")
    try:
        decoded = base64.b64decode(
            value + ("=" * (-len(value) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as exc:
        raise AiCredentialError("invalid encrypted credential payload") from exc
    if not decoded or len(decoded) > maximum:
        raise AiCredentialError("invalid encrypted credential payload")
    return decoded


def _uuid(value: object, *, label: str) -> str:
    try:
        parsed = uuid.UUID(str(value or ""))
    except (ValueError, AttributeError, TypeError) as exc:
        raise AiCredentialError(f"invalid {label}") from exc
    return str(parsed)


def _positive_version(value: object) -> int:
    if type(value) is not int or value < 1 or value > 2_147_483_647:
        raise AiCredentialError("invalid credential version")
    return value


def _credential_aad(
    *,
    user_id: str,
    provider: str,
    model_id: str,
    registry_version: str,
    version: int,
) -> bytes:
    return json.dumps(
        {
            "format": _CREDENTIAL_FORMAT,
            "model_id": model_id,
            "provider": provider,
            "registry_version": registry_version,
            "user_id": user_id,
            "version": version,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _device_aad(credential_aad: bytes, device_id: str) -> bytes:
    return credential_aad + b"\x00device_id=" + device_id.encode("ascii")


@dataclass(frozen=True, slots=True)
class DeviceCredentialEnvelope:
    credential_version: int
    device_id: str
    key_algorithm: str
    ephemeral_public_key: bytes
    nonce: bytes
    ciphertext: bytes

    def to_mapping(self) -> dict[str, object]:
        return {
            "credential_version": self.credential_version,
            "device_id": self.device_id,
            "key_algorithm": self.key_algorithm,
            "ephemeral_public_key": _b64(self.ephemeral_public_key),
            "nonce": _b64(self.nonce),
            "ciphertext": _b64(self.ciphertext),
        }

    @classmethod
    def from_mapping(cls, raw: Mapping) -> "DeviceCredentialEnvelope":
        if not isinstance(raw, Mapping):
            raise AiCredentialError("invalid encrypted credential payload")
        if set(raw) != {
            "credential_version",
            "device_id",
            "key_algorithm",
            "ephemeral_public_key",
            "nonce",
            "ciphertext",
        }:
            raise AiCredentialError("invalid encrypted credential payload")
        if raw.get("key_algorithm") != "p256":
            raise AiCredentialError("invalid encrypted credential payload")
        public_key = _unb64(raw.get("ephemeral_public_key"), maximum=65)
        if len(public_key) != 65:
            raise AiCredentialError("invalid encrypted credential payload")
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), public_key
            )
        except ValueError as exc:
            raise AiCredentialError(
                "invalid encrypted credential payload"
            ) from exc
        nonce = _unb64(raw.get("nonce"), maximum=12)
        if len(nonce) != 12:
            raise AiCredentialError("invalid encrypted credential payload")
        ciphertext = _unb64(raw.get("ciphertext"), maximum=48)
        if len(ciphertext) != 48:
            raise AiCredentialError("invalid encrypted credential payload")
        return cls(
            credential_version=_positive_version(
                raw.get("credential_version")
            ),
            device_id=_uuid(raw.get("device_id"), label="device id"),
            key_algorithm="p256",
            ephemeral_public_key=public_key,
            nonce=nonce,
            ciphertext=ciphertext,
        )


@dataclass(frozen=True, slots=True)
class EncryptedAiCredential:
    provider: str
    model_id: str
    credential_version: int
    nonce: bytes
    ciphertext: bytes
    device_envelopes: tuple[DeviceCredentialEnvelope, ...]

    def to_mapping(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "model_id": self.model_id,
            "credential_version": self.credential_version,
            "nonce": _b64(self.nonce),
            "ciphertext": _b64(self.ciphertext),
            "device_envelopes": [
                envelope.to_mapping() for envelope in self.device_envelopes
            ],
        }

    def to_rpc_payload(self) -> dict[str, object]:
        return self.to_mapping()

    @classmethod
    def from_mapping(cls, raw: Mapping) -> "EncryptedAiCredential":
        if not isinstance(raw, Mapping):
            raise AiCredentialError("invalid encrypted credential payload")
        if set(raw) != {
            "provider",
            "model_id",
            "credential_version",
            "nonce",
            "ciphertext",
            "device_envelopes",
        }:
            raise AiCredentialError("invalid encrypted credential payload")
        provider = str(raw.get("provider") or "")
        model_id = str(raw.get("model_id") or "")
        selection = resolve_provider(provider, model_id)
        credential_version = _positive_version(
            raw.get("credential_version")
        )
        nonce = _unb64(raw.get("nonce"), maximum=12)
        if len(nonce) != 12:
            raise AiCredentialError("invalid encrypted credential payload")
        raw_envelopes = raw.get("device_envelopes")
        if (
            not isinstance(raw_envelopes, list)
            or not raw_envelopes
            or len(raw_envelopes) > _MAX_ENVELOPES
        ):
            raise AiCredentialError("invalid encrypted credential payload")
        envelopes = tuple(
            DeviceCredentialEnvelope.from_mapping(item)
            for item in raw_envelopes
        )
        if len({item.device_id for item in envelopes}) != len(envelopes):
            raise AiCredentialError("invalid encrypted credential payload")
        if any(
            item.credential_version != credential_version
            for item in envelopes
        ):
            raise AiCredentialError("invalid encrypted credential payload")
        ciphertext = _unb64(
            raw.get("ciphertext"), maximum=_MAX_API_KEY_BYTES + 16
        )
        if len(ciphertext) < 17:
            raise AiCredentialError("invalid encrypted credential payload")
        return cls(
            provider=selection.provider,
            model_id=selection.model_id,
            credential_version=credential_version,
            nonce=nonce,
            ciphertext=ciphertext,
            device_envelopes=envelopes,
        )


class InMemoryAiCredential:
    """Minimal decrypted credential whose owned byte buffer can be zeroed."""

    __slots__ = (
        "provider",
        "model_id",
        "endpoint",
        "registry_version",
        "credential_version",
        "_api_key",
    )

    def __init__(
        self,
        *,
        provider: str,
        model_id: str,
        endpoint: str,
        registry_version: str,
        credential_version: int,
        api_key: bytes,
    ) -> None:
        self.provider = provider
        self.model_id = model_id
        self.endpoint = endpoint
        self.registry_version = registry_version
        self.credential_version = _positive_version(credential_version)
        self._api_key = bytearray(api_key)

    @property
    def cleared(self) -> bool:
        return not self._api_key

    def api_key_text(self) -> str:
        if self.cleared:
            raise CredentialClearedError("AI credential has been cleared")
        return self._api_key.decode("ascii")

    def clear(self) -> None:
        for index in range(len(self._api_key)):
            self._api_key[index] = 0
        self._api_key.clear()

    def __enter__(self) -> "InMemoryAiCredential":
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.clear()

    def __repr__(self) -> str:
        state = "cleared" if self.cleared else "loaded"
        return (
            "InMemoryAiCredential("
            f"provider={self.provider!r}, model_id={self.model_id!r}, "
            f"credential_version={self.credential_version!r}, "
            f"state={state!r})"
        )

    def __del__(self) -> None:
        buffer = getattr(self, "_api_key", None)
        if isinstance(buffer, bytearray):
            for index in range(len(buffer)):
                buffer[index] = 0
            buffer.clear()


@dataclass(frozen=True, slots=True)
class CredentialRewrapResult:
    status: Literal["rewrapped", "reentry_required"]
    credential: EncryptedAiCredential | None
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class _DesktopDevice:
    device_id: str
    public_key: bytes


def _decode_device_public_key(value: object) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    elif isinstance(value, str) and value.startswith("\\x"):
        try:
            raw = bytes.fromhex(value[2:])
        except ValueError as exc:
            raise CredentialDeviceError("invalid desktop device") from exc
    else:
        try:
            raw = _unb64(value, maximum=65)
        except AiCredentialError as exc:
            raise CredentialDeviceError("invalid desktop device") from exc
    if len(raw) != 65:
        raise CredentialDeviceError("invalid desktop device")
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError as exc:
        raise CredentialDeviceError("invalid desktop device") from exc
    return raw


def _desktop_device(raw: Mapping, *, user_id: str) -> _DesktopDevice:
    if not isinstance(raw, Mapping):
        raise CredentialDeviceError("invalid desktop device")
    if (
        str(raw.get("user_id") or "") != user_id
        or raw.get("status") != "active"
        or raw.get("key_algorithm") != "p256"
        or str(raw.get("device_kind") or "").strip().lower() != "desktop"
    ):
        raise CredentialDeviceError("active desktop P-256 device required")
    return _DesktopDevice(
        device_id=_uuid(raw.get("id") or raw.get("device_id"), label="device id"),
        public_key=_decode_device_public_key(raw.get("public_key")),
    )


def _eligible_devices(
    devices: Iterable[Mapping], *, user_id: str
) -> tuple[_DesktopDevice, ...]:
    eligible: list[_DesktopDevice] = []
    for raw in devices:
        try:
            eligible.append(_desktop_device(raw, user_id=user_id))
        except CredentialDeviceError:
            continue
    eligible.sort(key=lambda item: item.device_id)
    if not eligible or len(eligible) > _MAX_ENVELOPES:
        raise CredentialDeviceError("active desktop P-256 device required")
    if len({item.device_id for item in eligible}) != len(eligible):
        raise CredentialDeviceError("duplicate desktop device")
    return tuple(eligible)


def _seal_dek(
    dek: bytes,
    device: _DesktopDevice,
    *,
    credential_aad: bytes,
    credential_version: int,
) -> DeviceCredentialEnvelope:
    target_public = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), device.public_key
    )
    ephemeral_private = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public = ephemeral_private.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    aad = _device_aad(credential_aad, device.device_id)
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(aad).digest(),
        info=b"v9:user-ai-credential-kek:1",
    ).derive(ephemeral_private.exchange(ec.ECDH(), target_public))
    nonce = os.urandom(12)
    return DeviceCredentialEnvelope(
        credential_version=credential_version,
        device_id=device.device_id,
        key_algorithm="p256",
        ephemeral_public_key=ephemeral_public,
        nonce=nonce,
        ciphertext=AESGCM(wrapping_key).encrypt(nonce, dek, aad),
    )


def _open_dek(
    envelope: DeviceCredentialEnvelope,
    private_key: bytes | bytearray | ec.EllipticCurvePrivateKey,
    *,
    credential_aad: bytes,
) -> bytes:
    private_key = load_desktop_credential_private_key(private_key)
    ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), envelope.ephemeral_public_key
    )
    aad = _device_aad(credential_aad, envelope.device_id)
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(aad).digest(),
        info=b"v9:user-ai-credential-kek:1",
    ).derive(private_key.exchange(ec.ECDH(), ephemeral_public))
    return AESGCM(wrapping_key).decrypt(
        envelope.nonce, envelope.ciphertext, aad
    )


def _validate_api_key(api_key: str) -> bytes:
    if not isinstance(api_key, str):
        raise AiCredentialError("invalid AI credential")
    try:
        encoded = api_key.encode("ascii")
    except UnicodeEncodeError as exc:
        raise AiCredentialError("invalid AI credential") from exc
    if (
        not encoded
        or len(encoded) > _MAX_API_KEY_BYTES
        or any(value < 0x21 or value > 0x7E for value in encoded)
    ):
        raise AiCredentialError("invalid AI credential")
    return encoded


def encrypt_api_credential(
    api_key: str,
    *,
    user_id: str,
    provider: str,
    model_id: str,
    credential_version: int,
    devices: Iterable[Mapping],
    registry_version: str = REGISTRY_VERSION,
) -> EncryptedAiCredential:
    """Encrypt an API key and wrap its random DEK to eligible devices."""
    owner_id = _uuid(user_id, label="user id")
    selection = resolve_provider(
        provider, model_id, registry_version=registry_version
    )
    credential_version = _positive_version(credential_version)
    eligible = _eligible_devices(devices, user_id=owner_id)
    plaintext = bytearray(_validate_api_key(api_key))
    dek = bytearray(os.urandom(32))
    aad = _credential_aad(
        user_id=owner_id,
        provider=selection.provider,
        model_id=selection.model_id,
        registry_version=selection.registry_version,
        version=credential_version,
    )
    try:
        nonce = os.urandom(12)
        ciphertext = AESGCM(bytes(dek)).encrypt(nonce, bytes(plaintext), aad)
        envelopes = tuple(
            _seal_dek(
                bytes(dek),
                device,
                credential_aad=aad,
                credential_version=credential_version,
            )
            for device in eligible
        )
        return EncryptedAiCredential(
            provider=selection.provider,
            model_id=selection.model_id,
            credential_version=credential_version,
            nonce=nonce,
            ciphertext=ciphertext,
            device_envelopes=envelopes,
        )
    finally:
        for buffer in (plaintext, dek):
            for index in range(len(buffer)):
                buffer[index] = 0
            buffer.clear()


def _bound_context(
    encrypted: EncryptedAiCredential, *, user_id: str
) -> tuple[str, bytes]:
    owner_id = _uuid(user_id, label="user id")
    selection = resolve_provider(
        encrypted.provider,
        encrypted.model_id,
    )
    aad = _credential_aad(
        user_id=owner_id,
        provider=selection.provider,
        model_id=selection.model_id,
        registry_version=selection.registry_version,
        version=_positive_version(encrypted.credential_version),
    )
    return owner_id, aad


def decrypt_api_credential(
    encrypted: EncryptedAiCredential | Mapping,
    *,
    user_id: str,
    device: Mapping,
    device_private_key: bytes | bytearray | ec.EllipticCurvePrivateKey,
) -> InMemoryAiCredential:
    """Decrypt a credential into a redacted, clearable in-memory object."""
    if isinstance(encrypted, Mapping):
        encrypted = EncryptedAiCredential.from_mapping(encrypted)
    owner_id, aad = _bound_context(encrypted, user_id=user_id)
    desktop = _desktop_device(device, user_id=owner_id)
    envelope = next(
        (
            item
            for item in encrypted.device_envelopes
            if item.device_id == desktop.device_id
        ),
        None,
    )
    if envelope is None:
        raise CredentialDeviceError("credential envelope unavailable")
    try:
        dek = bytearray(
            _open_dek(envelope, device_private_key, credential_aad=aad)
        )
        plaintext = AESGCM(bytes(dek)).decrypt(
            encrypted.nonce, encrypted.ciphertext, aad
        )
        api_key = _validate_api_key(plaintext.decode("ascii"))
    except (InvalidTag, UnicodeError, AiCredentialError, ValueError) as exc:
        raise CredentialAuthenticationError(
            "credential authentication failed"
        ) from exc
    finally:
        if "dek" in locals():
            for index in range(len(dek)):
                dek[index] = 0
            dek.clear()
    selection = resolve_provider(
        encrypted.provider,
        encrypted.model_id,
    )
    return InMemoryAiCredential(
        provider=selection.provider,
        model_id=selection.model_id,
        endpoint=selection.endpoint,
        registry_version=selection.registry_version,
        credential_version=encrypted.credential_version,
        api_key=api_key,
    )


def rewrap_credential_for_new_device(
    encrypted: EncryptedAiCredential | Mapping,
    *,
    user_id: str,
    source_device: Mapping | None,
    source_private_key: bytes | bytearray | ec.EllipticCurvePrivateKey | None,
    target_device: Mapping,
) -> CredentialRewrapResult:
    """Wrap only the existing DEK to a new eligible desktop device."""
    if isinstance(encrypted, Mapping):
        encrypted = EncryptedAiCredential.from_mapping(encrypted)
    owner_id, aad = _bound_context(encrypted, user_id=user_id)
    target = _desktop_device(target_device, user_id=owner_id)
    existing_target = next(
        (
            item
            for item in encrypted.device_envelopes
            if item.device_id == target.device_id
        ),
        None,
    )
    if existing_target is not None:
        return CredentialRewrapResult("rewrapped", encrypted)
    if source_device is None or source_private_key is None:
        return CredentialRewrapResult(
            "reentry_required", None, "trusted_device_unavailable"
        )
    source = _desktop_device(source_device, user_id=owner_id)
    source_envelope = next(
        (
            item
            for item in encrypted.device_envelopes
            if item.device_id == source.device_id
        ),
        None,
    )
    if source_envelope is None:
        return CredentialRewrapResult(
            "reentry_required", None, "trusted_device_unavailable"
        )
    try:
        dek = bytearray(
            _open_dek(source_envelope, source_private_key, credential_aad=aad)
        )
        target_envelope = _seal_dek(
            bytes(dek),
            target,
            credential_aad=aad,
            credential_version=encrypted.credential_version,
        )
    except (InvalidTag, ValueError) as exc:
        raise CredentialAuthenticationError(
            "credential authentication failed"
        ) from exc
    finally:
        if "dek" in locals():
            for index in range(len(dek)):
                dek[index] = 0
            dek.clear()
    return CredentialRewrapResult(
        "rewrapped",
        replace(
            encrypted,
            device_envelopes=encrypted.device_envelopes + (target_envelope,),
        ),
    )
