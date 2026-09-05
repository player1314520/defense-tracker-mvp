"""Bounded structural validation for uploaded DOCX and PDF files.

The validators intentionally stop before extracting document content.  They are
designed to be called after the HTTP layer has read a bounded upload into bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any
import zipfile


DEFAULT_MAX_FILE_SIZE = 25 * 1024 * 1024
DEFAULT_MAX_DOCX_ENTRIES = 2_048
DEFAULT_MAX_DOCX_UNCOMPRESSED_SIZE = 100 * 1024 * 1024
DEFAULT_MAX_DOCX_MEMBER_SIZE = 32 * 1024 * 1024
DEFAULT_MAX_DOCX_MEMBER_RATIO = 100.0
DEFAULT_MAX_DOCX_TOTAL_RATIO = 50.0
DEFAULT_MAX_PDF_PAGES = 200


class UploadValidationError(ValueError):
    """A user-correctable upload rejection with a stable machine code."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


@dataclass(frozen=True, slots=True)
class UploadValidationResult:
    kind: str
    size: int
    archive_entries: int | None = None
    uncompressed_size: int | None = None
    page_count: int | None = None


def _payload_bytes(data: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("upload data must be bytes-like")
    return bytes(data)


def _require_positive_limit(name: str, value: int | float) -> None:
    if value <= 0:
        raise ValueError(f"{name} must be positive")


def _check_file_size(data: bytes, max_file_size: int) -> None:
    _require_positive_limit("max_file_size", max_file_size)
    if len(data) > max_file_size:
        raise UploadValidationError(
            "UPLOAD_TOO_LARGE",
            "上传文件超过大小限制",
            details={"max_file_size": max_file_size, "size": len(data)},
        )


def validate_upload_envelope(
    filename: str,
    data: bytes | bytearray | memoryview,
    *,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> UploadValidationResult:
    """Perform only fixed-cost checks that are safe in the parent process.

    Archive/PDF structure, entry/page counts and compression ratios intentionally
    remain the isolated worker's responsibility.  This function only examines
    the bounded byte length, final suffix and a constant-size magic prefix.
    """

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("upload data must be bytes-like")
    _require_positive_limit("max_file_size", max_file_size)
    size = len(data)
    if size > max_file_size:
        raise UploadValidationError(
            "UPLOAD_TOO_LARGE",
            "上传文件超过大小限制",
            details={"max_file_size": max_file_size, "size": size},
        )

    suffix = Path(filename or "").suffix.lower()
    if suffix == ".docx":
        if bytes(data[:4]) != b"PK\x03\x04":
            raise UploadValidationError("DOCX_MAGIC_MISMATCH", "DOCX 文件头无效")
        return UploadValidationResult(kind="docx", size=size)
    if suffix == ".pdf":
        if bytes(data[:5]) != b"%PDF-":
            raise UploadValidationError("PDF_MAGIC_MISMATCH", "PDF 文件头无效")
        return UploadValidationResult(kind="pdf", size=size)
    raise UploadValidationError(
        "UNSUPPORTED_UPLOAD_TYPE",
        "仅支持 DOCX 和 PDF 文件",
        details={"extension": suffix},
    )


def _is_unsafe_archive_name(name: str) -> bool:
    if not name or "\x00" in name:
        return True
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or normalized.startswith("//"):
        return True
    path = PurePosixPath(normalized)
    if ".." in path.parts:
        return True
    first_part = path.parts[0] if path.parts else ""
    return ":" in first_part


def _compression_ratio(uncompressed: int, compressed: int) -> float:
    if uncompressed == 0:
        return 0.0
    if compressed == 0:
        return float("inf")
    return uncompressed / compressed


def validate_docx(
    data: bytes | bytearray | memoryview,
    *,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_entries: int = DEFAULT_MAX_DOCX_ENTRIES,
    max_uncompressed_size: int = DEFAULT_MAX_DOCX_UNCOMPRESSED_SIZE,
    max_member_size: int = DEFAULT_MAX_DOCX_MEMBER_SIZE,
    max_member_compression_ratio: float = DEFAULT_MAX_DOCX_MEMBER_RATIO,
    max_total_compression_ratio: float = DEFAULT_MAX_DOCX_TOTAL_RATIO,
) -> UploadValidationResult:
    """Validate DOCX package structure and ZIP expansion bounds."""

    payload = _payload_bytes(data)
    _check_file_size(payload, max_file_size)
    for name, value in (
        ("max_entries", max_entries),
        ("max_uncompressed_size", max_uncompressed_size),
        ("max_member_size", max_member_size),
        ("max_member_compression_ratio", max_member_compression_ratio),
        ("max_total_compression_ratio", max_total_compression_ratio),
    ):
        _require_positive_limit(name, value)

    if not payload.startswith(b"PK\x03\x04"):
        raise UploadValidationError("DOCX_MAGIC_MISMATCH", "DOCX 文件头无效")

    try:
        with zipfile.ZipFile(BytesIO(payload)) as archive:
            members = archive.infolist()
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        raise UploadValidationError("DOCX_ARCHIVE_INVALID", "DOCX 压缩包无法解析") from exc

    if len(members) > max_entries:
        raise UploadValidationError(
            "DOCX_ENTRY_LIMIT_EXCEEDED",
            "DOCX 条目数超过限制",
            details={"entry_count": len(members), "max_entries": max_entries},
        )

    total_uncompressed = 0
    total_compressed = 0
    names: set[str] = set()
    for member in members:
        if _is_unsafe_archive_name(member.filename):
            raise UploadValidationError(
                "DOCX_UNSAFE_PATH",
                "DOCX 包含不安全的归档路径",
                details={"entry": member.filename},
            )
        if member.flag_bits & 0x1:
            raise UploadValidationError("DOCX_ENCRYPTED", "不支持加密 DOCX")
        if member.is_dir():
            continue
        names.add(member.filename.replace("\\", "/"))
        if member.file_size > max_member_size:
            raise UploadValidationError(
                "DOCX_MEMBER_LIMIT_EXCEEDED",
                "DOCX 单个条目解压后过大",
                details={"entry": member.filename, "max_member_size": max_member_size},
            )
        member_ratio = _compression_ratio(member.file_size, member.compress_size)
        if member_ratio > max_member_compression_ratio:
            raise UploadValidationError(
                "DOCX_COMPRESSION_RATIO_EXCEEDED",
                "DOCX 单个条目压缩比超过限制",
                details={"entry": member.filename, "max_ratio": max_member_compression_ratio},
            )
        total_uncompressed += member.file_size
        total_compressed += member.compress_size
        if total_uncompressed > max_uncompressed_size:
            raise UploadValidationError(
                "DOCX_UNCOMPRESSED_LIMIT_EXCEEDED",
                "DOCX 解压总量超过限制",
                details={
                    "max_uncompressed_size": max_uncompressed_size,
                    "uncompressed_size": total_uncompressed,
                },
            )

    total_ratio = _compression_ratio(total_uncompressed, total_compressed)
    if total_ratio > max_total_compression_ratio:
        raise UploadValidationError(
            "DOCX_TOTAL_COMPRESSION_RATIO_EXCEEDED",
            "DOCX 总压缩比超过限制",
            details={"max_ratio": max_total_compression_ratio},
        )

    required_parts = {"[Content_Types].xml", "_rels/.rels", "word/document.xml"}
    missing = sorted(required_parts - names)
    if missing:
        raise UploadValidationError(
            "DOCX_REQUIRED_PART_MISSING",
            "DOCX 缺少必要的 Word 组件",
            details={"missing": missing},
        )

    return UploadValidationResult(
        kind="docx",
        size=len(payload),
        archive_entries=len(members),
        uncompressed_size=total_uncompressed,
    )


def _pdf_reader_type():
    try:
        from pypdf import PdfReader

        return PdfReader
    except ImportError:
        try:
            from PyPDF2 import PdfReader

            return PdfReader
        except ImportError as exc:
            raise UploadValidationError(
                "PDF_PARSER_UNAVAILABLE",
                "PDF 安全解析器不可用",
            ) from exc


def validate_pdf(
    data: bytes | bytearray | memoryview,
    *,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_pages: int = DEFAULT_MAX_PDF_PAGES,
) -> UploadValidationResult:
    """Validate PDF magic, parseability, encryption state and page count."""

    payload = _payload_bytes(data)
    _check_file_size(payload, max_file_size)
    _require_positive_limit("max_pages", max_pages)
    if not payload.startswith(b"%PDF-"):
        raise UploadValidationError("PDF_MAGIC_MISMATCH", "PDF 文件头无效")

    PdfReader = _pdf_reader_type()
    try:
        reader = PdfReader(BytesIO(payload), strict=True)
        if getattr(reader, "is_encrypted", False):
            raise UploadValidationError("PDF_ENCRYPTED", "不支持加密 PDF")
        page_count = len(reader.pages)
    except UploadValidationError:
        raise
    except Exception as exc:
        raise UploadValidationError("PDF_PARSE_ERROR", "PDF 无法安全解析") from exc

    if page_count > max_pages:
        raise UploadValidationError(
            "PDF_PAGE_LIMIT_EXCEEDED",
            "PDF 页数超过限制",
            details={"max_pages": max_pages, "page_count": page_count},
        )
    return UploadValidationResult(kind="pdf", size=len(payload), page_count=page_count)


def validate_upload(
    filename: str,
    data: bytes | bytearray | memoryview,
    *,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    **limits: Any,
) -> UploadValidationResult:
    """Dispatch validation by the final filename suffix, then verify magic."""

    suffix = Path(filename or "").suffix.lower()
    if suffix == ".docx":
        return validate_docx(data, max_file_size=max_file_size, **limits)
    if suffix == ".pdf":
        return validate_pdf(data, max_file_size=max_file_size, **limits)
    raise UploadValidationError(
        "UNSUPPORTED_UPLOAD_TYPE",
        "仅支持 DOCX 和 PDF 文件",
        details={"extension": suffix},
    )


__all__ = [
    "UploadValidationError",
    "UploadValidationResult",
    "validate_docx",
    "validate_pdf",
    "validate_upload",
    "validate_upload_envelope",
]
