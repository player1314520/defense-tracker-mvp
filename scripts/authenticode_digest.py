# -*- coding: utf-8 -*-
"""Bind an unsigned PE image to its Authenticode-signed form.

Authenticode changes the PE checksum and certificate-table directory, then
appends an aligned WIN_CERTIFICATE table.  This module deliberately does not
verify the signature or certificate chain; the release signing gate owns that
job.  It only proves that signing did not change any other byte of the image.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal


_DOMAIN = b"DefenseTracker Authenticode-neutral PE body v1\0"
_ALGORITHM = "sha256-authenticode-neutral-pe-v1"
_PE32_MAGIC = 0x10B
_PE32_PLUS_MAGIC = 0x20B
_IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
_OPTIONAL_HEADER_MINIMUM = {_PE32_MAGIC: 224, _PE32_PLUS_MAGIC: 240}
_SECTION_HEADER_BYTES = 40
_MAX_SECTIONS = 96
_CHECKSUM_OFFSET_IN_OPTIONAL_HEADER = 64
_NUMBER_OF_RVA_AND_SIZES_OFFSET = 108
_DATA_DIRECTORY_OFFSET = 112
_SECURITY_DIRECTORY_INDEX = 4
_SECURITY_DIRECTORY_BYTES = 8
_KNOWN_CERTIFICATE_REVISIONS = {0x0100, 0x0200}
_KNOWN_CERTIFICATE_TYPES = {0x0001, 0x0002, 0x0003, 0x0004}


@dataclass(frozen=True)
class PeLayout:
    """Offsets needed to normalize and validate one PE image."""

    file_size: int
    checksum_offset: int
    security_directory_offset: int
    certificate_offset: int
    certificate_size: int

    @property
    def has_certificate_table(self) -> bool:
        return self.certificate_offset != 0


@dataclass(frozen=True)
class AuthenticodeImageDigest:
    """Stable, serializable evidence for one inspected PE executable."""

    algorithm: str
    file_sha256: str
    bytes: int
    normalized_sha256: str
    signature_state: Literal["unsigned", "signed"]
    certificate_table_offset: int
    certificate_table_bytes: int
    unsigned_bytes: int


def _unpack_from(fmt: str, data: bytes, offset: int, *, field: str) -> tuple[int, ...]:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise ValueError(f"PE {field} is outside the file")
    return struct.unpack_from(fmt, data, offset)


def _align_8(value: int) -> int:
    return (value + 7) & ~7


def _validate_certificate_table(data: bytes, offset: int, size: int) -> None:
    end = offset + size
    cursor = offset
    entries = 0
    while cursor < end:
        if end - cursor < 8:
            raise ValueError("PE certificate table has a truncated WIN_CERTIFICATE header")
        length, revision, certificate_type = _unpack_from(
            "<IHH", data, cursor, field="WIN_CERTIFICATE header"
        )
        if length < 8 or cursor + length > end:
            raise ValueError("PE certificate table has an invalid WIN_CERTIFICATE length")
        if revision not in _KNOWN_CERTIFICATE_REVISIONS:
            raise ValueError("PE certificate table has an unknown certificate revision")
        if certificate_type not in _KNOWN_CERTIFICATE_TYPES:
            raise ValueError("PE certificate table has an unknown certificate type")
        entries += 1
        unaligned_end = cursor + length
        if unaligned_end == end:
            cursor = end
            continue
        aligned_end = _align_8(unaligned_end)
        if aligned_end > end:
            raise ValueError("PE certificate table has truncated entry alignment")
        if any(data[unaligned_end:aligned_end]):
            raise ValueError("PE certificate table entry padding is not zero")
        cursor = aligned_end
    if entries == 0:
        raise ValueError("PE certificate table is empty")


def parse_pe(data: bytes) -> PeLayout:
    """Strictly parse a PE32 or PE32+ executable layout."""

    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("File is not a complete DOS/PE image")
    (pe_offset,) = _unpack_from("<I", data, 0x3C, field="DOS e_lfanew")
    if pe_offset < 64 or pe_offset + 24 > len(data):
        raise ValueError("PE header offset is invalid")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("PE signature is missing")

    coff_offset = pe_offset + 4
    machine, section_count = _unpack_from(
        "<HH", data, coff_offset, field="COFF header"
    )
    (optional_size,) = _unpack_from(
        "<H", data, coff_offset + 16, field="COFF optional-header size"
    )
    (characteristics,) = _unpack_from(
        "<H", data, coff_offset + 18, field="COFF characteristics"
    )
    if machine == 0:
        raise ValueError("PE machine type is invalid")
    if not 1 <= section_count <= _MAX_SECTIONS:
        raise ValueError("PE section count is invalid")
    if characteristics & _IMAGE_FILE_EXECUTABLE_IMAGE == 0:
        raise ValueError("PE image is not marked executable")
    optional_offset = coff_offset + 20
    optional_end = optional_offset + optional_size
    if optional_end > len(data):
        raise ValueError("PE optional header is outside the file")
    (magic,) = _unpack_from("<H", data, optional_offset, field="optional-header magic")
    if magic not in {_PE32_MAGIC, _PE32_PLUS_MAGIC}:
        raise ValueError("PE optional-header magic is unsupported")
    if optional_size < _OPTIONAL_HEADER_MINIMUM[magic]:
        raise ValueError("PE optional header is truncated")
    if magic == _PE32_MAGIC:
        number_of_directories_offset = 92
        data_directory_offset = 96
    else:
        number_of_directories_offset = _NUMBER_OF_RVA_AND_SIZES_OFFSET
        data_directory_offset = _DATA_DIRECTORY_OFFSET
    (file_alignment,) = _unpack_from(
        "<I", data, optional_offset + 36, field="FileAlignment"
    )
    (size_of_image,) = _unpack_from(
        "<I", data, optional_offset + 56, field="SizeOfImage"
    )
    (size_of_headers,) = _unpack_from(
        "<I", data, optional_offset + 60, field="SizeOfHeaders"
    )
    (directory_count,) = _unpack_from(
        "<I",
        data,
        optional_offset + number_of_directories_offset,
        field="NumberOfRvaAndSizes",
    )
    if (
        file_alignment < 512
        or file_alignment > 65536
        or file_alignment & (file_alignment - 1)
    ):
        raise ValueError("PE FileAlignment is invalid")
    if size_of_image == 0:
        raise ValueError("PE SizeOfImage is zero")
    if directory_count <= _SECURITY_DIRECTORY_INDEX:
        raise ValueError("PE security directory is missing")

    security_directory_offset = (
        optional_offset
        + data_directory_offset
        + _SECURITY_DIRECTORY_INDEX * _SECURITY_DIRECTORY_BYTES
    )
    if security_directory_offset + _SECURITY_DIRECTORY_BYTES > optional_end:
        raise ValueError("PE security directory is outside the optional header")
    certificate_offset, certificate_size = _unpack_from(
        "<II", data, security_directory_offset, field="security directory"
    )
    if (certificate_offset == 0) != (certificate_size == 0):
        raise ValueError("PE security directory is only partially populated")

    section_table_offset = optional_end
    section_table_end = section_table_offset + section_count * _SECTION_HEADER_BYTES
    content_end = certificate_offset or len(data)
    if (
        section_table_end > len(data)
        or size_of_headers < section_table_end
        or size_of_headers > content_end
        or size_of_headers % file_alignment
    ):
        raise ValueError("PE section table or SizeOfHeaders is invalid")

    last_section_end = size_of_headers
    for index in range(section_count):
        section_offset = section_table_offset + index * _SECTION_HEADER_BYTES
        raw_size, raw_offset = _unpack_from(
            "<II", data, section_offset + 16, field=f"section {index} raw range"
        )
        if raw_size == 0:
            continue
        if (
            raw_offset < size_of_headers
            or raw_offset % file_alignment
            or raw_offset + raw_size > content_end
        ):
            raise ValueError(f"PE section {index} raw range is invalid")
        last_section_end = max(last_section_end, raw_offset + raw_size)

    if certificate_offset:
        if (
            certificate_offset % 8
            or certificate_size < 8
            or certificate_size % 8
            or certificate_offset < last_section_end
            or certificate_offset + certificate_size != len(data)
        ):
            raise ValueError("PE certificate table must be aligned and end at EOF")
        _validate_certificate_table(data, certificate_offset, certificate_size)

    return PeLayout(
        file_size=len(data),
        checksum_offset=optional_offset + _CHECKSUM_OFFSET_IN_OPTIONAL_HEADER,
        security_directory_offset=security_directory_offset,
        certificate_offset=certificate_offset,
        certificate_size=certificate_size,
    )


def _neutral_sha256(data: bytes, layout: PeLayout, *, unsigned_size: int) -> str:
    if unsigned_size < layout.security_directory_offset + _SECURITY_DIRECTORY_BYTES:
        raise ValueError("Unsigned PE size does not contain the normalized header fields")
    body = bytearray(data[:unsigned_size])
    body[layout.checksum_offset : layout.checksum_offset + 4] = b"\0" * 4
    body[
        layout.security_directory_offset : layout.security_directory_offset
        + _SECURITY_DIRECTORY_BYTES
    ] = b"\0" * _SECURITY_DIRECTORY_BYTES
    digest = hashlib.sha256()
    digest.update(_DOMAIN)
    digest.update(unsigned_size.to_bytes(8, "little"))
    digest.update(body)
    return digest.hexdigest()


def unsigned_pe_neutral_sha256(path: Path) -> str:
    """Return a normalized digest for an unsigned release PE image."""

    return inspect_authenticode_image(path, require_state="unsigned").normalized_sha256


def verify_pe_after_signing(
    path: Path,
    *,
    unsigned_size: int,
    expected_neutral_sha256: str,
    allow_exact_unsigned: bool = False,
) -> str:
    """Verify that ``path`` differs from the reviewed PE only by signing.

    ``unsigned_size`` is the reviewed pre-sign EOF.  A signed file may only add
    zero bytes up to the next 8-byte boundary and a certificate table ending at
    its new EOF.  The normalized body digest binds every other byte.
    """

    try:
        inspected = inspect_authenticode_image(
            path,
            require_state="signed",
            expected_unsigned_size=unsigned_size,
            expected_normalized_sha256=expected_neutral_sha256,
        )
    except ValueError:
        if not allow_exact_unsigned:
            raise
        inspected = inspect_authenticode_image(
            path,
            require_state="unsigned",
            expected_unsigned_size=unsigned_size,
            expected_normalized_sha256=expected_neutral_sha256,
        )
    return inspected.normalized_sha256


def inspect_authenticode_image(
    path: Path,
    *,
    require_state: Literal["unsigned", "signed"],
    expected_unsigned_size: int | None = None,
    expected_normalized_sha256: str | None = None,
) -> AuthenticodeImageDigest:
    """Inspect and bind an unsigned or signed PE executable.

    Signed inspection requires the reviewed pre-sign file size.  This removes
    ambiguity about where the original image ended and ensures that the only
    appended bytes before the certificate table are at most seven zero bytes.
    """

    if require_state not in {"unsigned", "signed"}:
        raise ValueError("require_state must be 'unsigned' or 'signed'")
    if path.is_symlink() or not path.is_file():
        raise ValueError("PE image must be a regular file")
    if expected_unsigned_size is not None and (
        not isinstance(expected_unsigned_size, int) or expected_unsigned_size <= 0
    ):
        raise ValueError("Expected unsigned PE size is invalid")
    if expected_normalized_sha256 is not None and (
        len(expected_normalized_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in expected_normalized_sha256
        )
    ):
        raise ValueError("Expected Authenticode-neutral SHA-256 is invalid")

    data = path.read_bytes()
    layout = parse_pe(data)
    state: Literal["unsigned", "signed"] = (
        "signed" if layout.has_certificate_table else "unsigned"
    )
    if state != require_state:
        raise ValueError(f"PE signature state is {state}, expected {require_state}")

    if state == "unsigned":
        unsigned_size = len(data)
        if expected_unsigned_size is not None and expected_unsigned_size != unsigned_size:
            raise ValueError("Unsigned PE size differs from the reviewed size")
    else:
        if expected_unsigned_size is None:
            raise ValueError("Signed PE inspection requires expected_unsigned_size")
        unsigned_size = expected_unsigned_size
        expected_certificate_offset = _align_8(unsigned_size)
        if layout.certificate_offset != expected_certificate_offset:
            raise ValueError("PE certificate table does not immediately follow reviewed bytes")
        if len(data) <= unsigned_size:
            raise ValueError("Signed PE did not append a certificate table")
        if any(data[unsigned_size:expected_certificate_offset]):
            raise ValueError("PE signing alignment padding is not zero")

    if len(data) < unsigned_size:
        raise ValueError("PE image is shorter than the reviewed image")
    normalized = _neutral_sha256(data, layout, unsigned_size=unsigned_size)
    if (
        expected_normalized_sha256 is not None
        and normalized != expected_normalized_sha256
    ):
        raise ValueError("PE body changed outside Authenticode fields")
    return AuthenticodeImageDigest(
        algorithm=_ALGORITHM,
        file_sha256=hashlib.sha256(data).hexdigest(),
        bytes=len(data),
        normalized_sha256=normalized,
        signature_state=state,
        certificate_table_offset=layout.certificate_offset,
        certificate_table_bytes=layout.certificate_size,
        unsigned_bytes=unsigned_size,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", type=Path, required=True)
    parser.add_argument(
        "--require-state", choices=("unsigned", "signed"), required=True
    )
    parser.add_argument("--expected-unsigned-size", type=int)
    parser.add_argument("--expected-normalized-sha256")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = inspect_authenticode_image(
        args.path,
        require_state=args.require_state,
        expected_unsigned_size=args.expected_unsigned_size,
        expected_normalized_sha256=args.expected_normalized_sha256,
    )
    rendered = json.dumps(asdict(result), indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(rendered, end="")
    else:
        destination = args.output.resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_text(rendered, encoding="utf-8", newline="\n")
        os.replace(temporary, destination)
        print("authenticode-image: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
