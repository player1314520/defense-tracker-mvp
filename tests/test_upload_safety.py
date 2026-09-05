from __future__ import annotations

import builtins
from io import BytesIO
import zipfile

import pytest

from upload_safety import (
    UploadValidationError,
    validate_docx,
    validate_pdf,
    validate_upload,
    validate_upload_envelope,
)


def _docx_bytes(*, extra_entries: dict[str, bytes] | None = None) -> bytes:
    output = BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("_rels/.rels", b"<Relationships/>")
        archive.writestr("word/document.xml", b"<w:document/>")
        for name, payload in (extra_entries or {}).items():
            archive.writestr(name, payload)
    return output.getvalue()


def _pdf_bytes(page_count: int, *, password: str | None = None) -> bytes:
    from reportlab.pdfgen.canvas import Canvas
    from reportlab.lib.pdfencrypt import StandardEncryption

    output = BytesIO()
    encryption = None if password is None else StandardEncryption(password, ownerPassword="owner")
    writer = Canvas(output, pagesize=(72, 72), encrypt=encryption)
    for _ in range(page_count):
        writer.showPage()
    writer.save()
    return output.getvalue()


def test_validate_upload_rejects_fake_docx_extension() -> None:
    with pytest.raises(UploadValidationError) as caught:
        validate_upload("report.docx", b"not a zip archive")

    assert caught.value.code == "DOCX_MAGIC_MISMATCH"


def test_validate_docx_accepts_minimal_valid_package() -> None:
    result = validate_docx(_docx_bytes())

    assert result.kind == "docx"
    assert result.archive_entries == 3
    assert result.page_count is None


def test_validate_docx_rejects_missing_word_document() -> None:
    output = BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")

    with pytest.raises(UploadValidationError) as caught:
        validate_docx(output.getvalue())

    assert caught.value.code == "DOCX_REQUIRED_PART_MISSING"


@pytest.mark.parametrize("unsafe_name", ["../outside.txt", "/absolute.txt", "word/../../escape.xml", "C:/escape.xml", "word\\..\\escape.xml"])
def test_validate_docx_rejects_path_traversal(unsafe_name: str) -> None:
    payload = _docx_bytes(extra_entries={unsafe_name: b"unsafe"})

    with pytest.raises(UploadValidationError) as caught:
        validate_docx(payload)

    assert caught.value.code == "DOCX_UNSAFE_PATH"


def test_validate_docx_rejects_zip_bomb_compression_ratio() -> None:
    payload = _docx_bytes(extra_entries={"word/media/bomb.bin": b"0" * 200_000})

    with pytest.raises(UploadValidationError) as caught:
        validate_docx(payload, max_member_compression_ratio=20)

    assert caught.value.code == "DOCX_COMPRESSION_RATIO_EXCEEDED"


def test_validate_docx_rejects_total_compression_ratio() -> None:
    payload = _docx_bytes(
        extra_entries={
            "word/media/a.bin": b"A" * 20_000,
            "word/media/b.bin": b"B" * 20_000,
        }
    )

    with pytest.raises(UploadValidationError) as caught:
        validate_docx(
            payload,
            max_member_compression_ratio=10_000,
            max_total_compression_ratio=20,
        )

    assert caught.value.code == "DOCX_TOTAL_COMPRESSION_RATIO_EXCEEDED"


def test_validate_docx_rejects_single_expanded_member_limit() -> None:
    payload = _docx_bytes(extra_entries={"word/media/large.bin": b"x" * 128})

    with pytest.raises(UploadValidationError) as caught:
        validate_docx(
            payload,
            max_member_size=64,
            max_member_compression_ratio=10_000,
        )

    assert caught.value.code == "DOCX_MEMBER_LIMIT_EXCEEDED"


def test_validate_docx_rejects_entry_and_uncompressed_limits() -> None:
    payload = _docx_bytes(extra_entries={"word/a.xml": b"a" * 32, "word/b.xml": b"b" * 32})

    with pytest.raises(UploadValidationError) as entry_error:
        validate_docx(payload, max_entries=4)
    assert entry_error.value.code == "DOCX_ENTRY_LIMIT_EXCEEDED"

    with pytest.raises(UploadValidationError) as size_error:
        validate_docx(payload, max_uncompressed_size=50)
    assert size_error.value.code == "DOCX_UNCOMPRESSED_LIMIT_EXCEEDED"


def test_validate_pdf_rejects_fake_pdf_extension() -> None:
    with pytest.raises(UploadValidationError) as caught:
        validate_upload("report.pdf", b"not a pdf")

    assert caught.value.code == "PDF_MAGIC_MISMATCH"


def test_validate_pdf_accepts_valid_minimal_sample() -> None:
    result = validate_pdf(_pdf_bytes(1), max_pages=1)

    assert result.kind == "pdf"
    assert result.page_count == 1
    assert result.archive_entries is None


def test_validate_pdf_uses_only_locked_parser_dependencies(monkeypatch) -> None:
    payload = _pdf_bytes(1)
    original_import = builtins.__import__

    def locked_import(name, *args, **kwargs):
        if name.split(".")[0] in {"pypdf", "PyPDF2"}:
            raise ModuleNotFoundError(name)
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", locked_import)

    assert validate_pdf(payload, max_pages=1).page_count == 1


@pytest.mark.parametrize("password", ["", "secret"])
def test_validate_pdf_rejects_encryption_even_with_empty_password(password) -> None:
    with pytest.raises(UploadValidationError) as caught:
        validate_pdf(_pdf_bytes(1, password=password))

    assert caught.value.code == "PDF_ENCRYPTED"


def test_validate_pdf_rejects_invalid_structure() -> None:
    with pytest.raises(UploadValidationError) as caught:
        validate_pdf(b"%PDF-1.7\nnot a document\n%%EOF")

    assert caught.value.code == "PDF_PARSE_ERROR"


def test_validate_pdf_rejects_page_limit() -> None:
    with pytest.raises(UploadValidationError) as caught:
        validate_pdf(_pdf_bytes(3), max_pages=2)

    assert caught.value.code == "PDF_PAGE_LIMIT_EXCEEDED"
    assert caught.value.details == {"max_pages": 2, "page_count": 3}


def test_validate_upload_rejects_unsupported_extension() -> None:
    with pytest.raises(UploadValidationError) as caught:
        validate_upload("report.exe", b"MZ")

    assert caught.value.code == "UNSUPPORTED_UPLOAD_TYPE"


def test_validate_upload_enforces_caller_file_size_limit_first() -> None:
    with pytest.raises(UploadValidationError) as caught:
        validate_upload("report.pdf", b"%PDF-1.7 too large", max_file_size=8)

    assert caught.value.code == "UPLOAD_TOO_LARGE"
    assert caught.value.details == {"max_file_size": 8, "size": 18}


def test_parent_envelope_docx_check_does_not_open_zip(monkeypatch) -> None:
    monkeypatch.setattr(
        zipfile,
        "ZipFile",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("parent envelope check must not inspect ZIP structure")
        ),
    )

    result = validate_upload_envelope("report.docx", b"PK\x03\x04untrusted")

    assert result.kind == "docx"
    assert result.archive_entries is None


def test_parent_envelope_pdf_check_does_not_load_pdf_parser(monkeypatch) -> None:
    import upload_safety

    monkeypatch.setattr(
        upload_safety,
        "_pdf_parser_types",
        lambda: (_ for _ in ()).throw(
            AssertionError("parent envelope check must not inspect PDF structure")
        ),
    )

    result = validate_upload_envelope("report.pdf", b"%PDF-untrusted")

    assert result.kind == "pdf"
    assert result.page_count is None
