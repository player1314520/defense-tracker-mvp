from io import BytesIO
import os
import types
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from docx import Document
from reportlab.pdfgen import canvas

import document_safety


def _docx_bytes(text: str = "bounded document") -> bytes:
    buffer = BytesIO()
    doc = Document()
    doc.add_paragraph(text)
    doc.save(buffer)
    return buffer.getvalue()


def _pdf_bytes(text: str = "bounded pdf") -> bytes:
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer)
    pdf.drawString(72, 720, text)
    pdf.save()
    return buffer.getvalue()


def _custom_docx(entries: dict[str, bytes]) -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        for name, value in entries.items():
            archive.writestr(name, value)
    return buffer.getvalue()


def test_docx_validation_accepts_normal_document_and_reports_bounds():
    payload = _docx_bytes("safe-docx-marker")
    report = document_safety.validate_docx(payload)

    assert report.entries > 1
    assert report.expanded_bytes > report.compressed_bytes
    assert document_safety.extract_docx_text_safe(payload) == "safe-docx-marker"


@pytest.mark.parametrize(
    ("entries", "code"),
    [
        (
            {
                "[Content_Types].xml": b"<Types/>",
                "word/document.xml": b"<document/>",
                "../outside.txt": b"x",
            },
            "DOCX_DANGEROUS_ENTRY",
        ),
        (
            {
                "[Content_Types].xml": b"<Types/>",
                "word/document.xml": b"<document/>",
                "word/embeddings/archive.zip": b"PK\x03\x04",
            },
            "DOCX_DANGEROUS_ENTRY",
        ),
        (
            {
                "[Content_Types].xml": b"<!DOCTYPE x [<!ENTITY y 'z'>]><Types/>",
                "word/document.xml": b"<document/>",
            },
            "DOCX_XML_DIRECTIVE",
        ),
    ],
)
def test_docx_validation_rejects_dangerous_container_entries(entries, code):
    with pytest.raises(document_safety.DocumentSafetyError) as exc:
        document_safety.validate_docx(_custom_docx(entries))

    assert exc.value.code == code


def test_docx_validation_rejects_expansion_and_ratio_before_python_docx():
    payload = _custom_docx(
        {
            "[Content_Types].xml": b"<Types/>",
            "word/document.xml": b"<document/>",
            "word/huge.xml": b"A" * (2 * 1024 * 1024),
        }
    )

    with pytest.raises(document_safety.DocumentSafetyError) as exc:
        document_safety.validate_docx(payload, max_compression_ratio=20)

    assert exc.value.code == "DOCX_COMPRESSION_RATIO"


def test_pdf_validation_rejects_wrong_magic_and_active_content():
    with pytest.raises(document_safety.DocumentSafetyError) as wrong_magic:
        document_safety.validate_pdf(b"not a pdf")
    assert wrong_magic.value.code == "PDF_BAD_MAGIC"

    active = b"%PDF-1.7\n1 0 obj << /OpenAction 2 0 R >> endobj\n%%EOF"
    with pytest.raises(document_safety.DocumentSafetyError) as active_error:
        document_safety.validate_pdf(active)
    assert active_error.value.code == "PDF_ACTIVE_CONTENT"


def test_pdf_extraction_runs_in_terminable_subprocess():
    text = document_safety.extract_pdf_text_isolated(
        _pdf_bytes("isolated-parser-marker"),
        max_pages=2,
        max_chars=2000,
        timeout_seconds=20,
    )

    assert "isolated-parser-marker" in text


def test_pdf_extraction_converts_timeout_to_stable_error(monkeypatch):
    def timeout(*args, **kwargs):
        raise document_safety.subprocess.TimeoutExpired(cmd="worker", timeout=1)

    monkeypatch.setattr(document_safety.subprocess, "run", timeout)

    with pytest.raises(document_safety.DocumentSafetyError) as exc:
        document_safety.extract_pdf_text_isolated(_pdf_bytes(), timeout_seconds=1)

    assert exc.value.code == "PDF_PARSE_TIMEOUT"
    assert "worker" not in str(exc.value)


def test_pdf_worker_environment_drops_credentials(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-cross-parser-boundary")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "must-not-cross-parser-boundary")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-cross-parser-boundary")
    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))

    worker_environment = document_safety._pdf_worker_environment()

    assert "OPENAI_API_KEY" not in worker_environment
    assert "SUPABASE_SERVICE_ROLE_KEY" not in worker_environment
    assert "AWS_SECRET_ACCESS_KEY" not in worker_environment
    assert worker_environment.get("PATH") == os.environ.get("PATH", "")
    assert worker_environment["PYTHONHASHSEED"] == "0"


def test_windows_worker_limit_setup_is_mandatory(monkeypatch):
    sentinel = object()
    monkeypatch.setattr(document_safety, "_RUNNING_ON_WINDOWS", True)
    monkeypatch.setattr(
        document_safety,
        "_create_and_assign_windows_job",
        lambda: sentinel,
    )
    monkeypatch.setattr(document_safety, "_WINDOWS_JOB_HANDLE", None)

    document_safety._apply_worker_limits()

    assert document_safety._WINDOWS_JOB_HANDLE is sentinel


def test_windows_worker_limit_setup_fails_closed(monkeypatch):
    def fail_job_setup():
        raise OSError("simulated job setup failure")

    monkeypatch.setattr(document_safety, "_RUNNING_ON_WINDOWS", True)
    monkeypatch.setattr(
        document_safety,
        "_create_and_assign_windows_job",
        fail_job_setup,
    )

    with pytest.raises(OSError, match="simulated job setup failure"):
        document_safety._apply_worker_limits()


def test_frozen_pdf_parser_reenters_signed_executable_worker(monkeypatch):
    captured: list[str] = []

    def completed(command, **_kwargs):
        captured.extend(command)
        document_safety.Path(command[-1]).write_text(
            '{"ok": true, "text": "isolated frozen text"}', encoding="utf-8"
        )
        return types.SimpleNamespace(
            returncode=0,
            stdout="",
        )

    monkeypatch.setattr(document_safety.sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        document_safety.sys,
        "executable",
        r"C:\Program Files\DefenseTracker\DefenseTracker.exe",
    )
    monkeypatch.delenv("DEFENSE_TRACKER_PDF_WORKER_PYTHON", raising=False)
    monkeypatch.setattr(document_safety.subprocess, "run", completed)

    assert document_safety.extract_pdf_text_isolated(_pdf_bytes()) == "isolated frozen text"
    assert captured[:2] == [
        r"C:\Program Files\DefenseTracker\DefenseTracker.exe",
        "--defense-tracker-pdf-worker",
    ]
    assert "-I" not in captured
