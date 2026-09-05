import subprocess
import sys
import json
import os
import tempfile
import threading
from io import BytesIO
from pathlib import Path

import pytest
from docx import Document
import isolated_document_parser

from isolated_document_parser import (
    DOCUMENT_WORKER_MEMORY_LIMIT_BYTES,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    IsolatedDocumentParseError,
    _bind_worker_job,
    _wait_for_worker,
    parse_document_isolated,
)


def _docx_bytes(text="normal document text"):
    stream = BytesIO()
    document = Document()
    document.add_paragraph(text)
    document.save(stream)
    return stream.getvalue()


def test_parser_queue_defaults_to_two_workers():
    assert isolated_document_parser.DOCUMENT_PARSE_MAX_WORKERS == 2


def test_parser_queue_full_fails_fast_with_retry_details(monkeypatch):
    slots = threading.BoundedSemaphore(1)
    assert slots.acquire(blocking=False) is True
    monkeypatch.setattr(
        isolated_document_parser, "_DOCUMENT_PARSE_SLOTS", slots, raising=False
    )
    monkeypatch.setattr(
        isolated_document_parser,
        "DOCUMENT_PARSE_RETRY_AFTER_SECONDS",
        7,
        raising=False,
    )

    with pytest.raises(IsolatedDocumentParseError) as caught:
        parse_document_isolated("docx", _docx_bytes(), "busy.docx", timeout=1)

    assert caught.value.code == "DOCUMENT_PARSE_QUEUE_FULL"
    assert caught.value.details == {"retry_after": 7}
    slots.release()


def test_parser_slot_is_released_after_success(monkeypatch):
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(
        isolated_document_parser, "_DOCUMENT_PARSE_SLOTS", slots, raising=False
    )

    parsed = parse_document_isolated(
        "docx", _docx_bytes("slot released"), "safe.docx", timeout=10
    )

    assert parsed["text"] == "slot released"
    assert slots.acquire(blocking=False) is True
    slots.release()


def test_parser_slot_is_released_after_timeout(monkeypatch):
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(
        isolated_document_parser, "_DOCUMENT_PARSE_SLOTS", slots, raising=False
    )
    monkeypatch.setattr(
        isolated_document_parser,
        "_worker_command",
        lambda *_args: [sys.executable, "-c", "import time; time.sleep(30)"],
    )

    with pytest.raises(IsolatedDocumentParseError) as caught:
        parse_document_isolated(
            "docx", _docx_bytes("blocked"), "blocked.docx", timeout=0.1
        )

    assert caught.value.code == "DOCUMENT_PARSE_TIMEOUT"
    assert slots.acquire(blocking=False) is True
    slots.release()


def test_blocked_parser_process_is_killed_and_next_document_still_parses():
    blocked = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    with pytest.raises(IsolatedDocumentParseError) as caught:
        _wait_for_worker(blocked, timeout=0.1)

    assert caught.value.code == "DOCUMENT_PARSE_TIMEOUT"
    assert blocked.poll() is not None

    parsed = parse_document_isolated(
        "docx", _docx_bytes("recovered parser"), "safe.docx", timeout=10
    )
    assert parsed["text"] == "recovered parser"


def test_parse_timeout_kills_real_worker_and_next_document_recovers(monkeypatch):
    original_command = isolated_document_parser._worker_command
    monkeypatch.setattr(
        isolated_document_parser,
        "_worker_command",
        lambda *_args: [sys.executable, "-c", "import time; time.sleep(30)"],
    )

    with pytest.raises(IsolatedDocumentParseError) as caught:
        parse_document_isolated(
            "docx", _docx_bytes("blocked"), "blocked.docx", timeout=0.1
        )

    assert caught.value.code == "DOCUMENT_PARSE_TIMEOUT"
    monkeypatch.setattr(isolated_document_parser, "_worker_command", original_command)
    parsed = parse_document_isolated(
        "docx", _docx_bytes("worker recovered"), "safe.docx", timeout=10
    )
    assert parsed["text"] == "worker recovered"


def test_windows_worker_job_sets_kill_on_close_and_memory_limit():
    calls = []

    class FakeApi:
        def create(self):
            calls.append(("create",))
            return 41

        def configure(self, handle, *, limit_flags, process_memory_limit):
            calls.append(("configure", handle, limit_flags, process_memory_limit))

        def assign(self, handle, process_handle):
            calls.append(("assign", handle, process_handle))

        def close(self, handle):
            calls.append(("close", handle))

    class FakeProcess:
        _handle = 73

    worker_job = _bind_worker_job(FakeProcess(), platform="nt", api=FakeApi())

    assert calls == [
        ("create",),
        (
            "configure",
            41,
            JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            DOCUMENT_WORKER_MEMORY_LIMIT_BYTES,
        ),
        ("assign", 41, 73),
    ]
    worker_job.close()
    worker_job.close()
    assert calls[-1] == ("close", 41)
    assert calls.count(("close", 41)) == 1


def test_windows_job_setup_failure_terminates_worker_fail_closed(monkeypatch):
    processes = []

    class FakeProcess:
        _handle = 101

        def __init__(self):
            self.returncode = None
            self.terminated = False

        def poll(self):
            return self.returncode

        def terminate(self):
            self.terminated = True
            self.returncode = 1

        def wait(self, timeout=None):
            return self.returncode

    def fake_popen(*_args, **_kwargs):
        process = FakeProcess()
        processes.append(process)
        return process

    monkeypatch.setattr(isolated_document_parser.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        isolated_document_parser,
        "_bind_worker_job",
        lambda _process: (_ for _ in ()).throw(OSError("job setup failed")),
    )

    with pytest.raises(IsolatedDocumentParseError) as caught:
        parse_document_isolated("docx", _docx_bytes(), "safe.docx", timeout=1)

    assert caught.value.code == "DOCUMENT_PARSER_ISOLATION_FAILED"
    assert processes and processes[0].terminated is True


def test_worker_spawn_failure_has_stable_isolation_code_and_releases_slot(monkeypatch):
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(isolated_document_parser, "_DOCUMENT_PARSE_SLOTS", slots)
    monkeypatch.setattr(
        isolated_document_parser.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("process creation denied")
        ),
    )

    with pytest.raises(IsolatedDocumentParseError) as caught:
        parse_document_isolated("docx", _docx_bytes(), "safe.docx", timeout=1)

    assert caught.value.code == "DOCUMENT_PARSER_ISOLATION_FAILED"
    assert slots.acquire(blocking=False) is True
    slots.release()


def test_worker_job_handle_is_released_after_success(monkeypatch):
    observed = {}

    class FakeProcess:
        _handle = 102

        def poll(self):
            return 0

        def wait(self, timeout=None):
            return 0

    class FakeJob:
        closed = False

        def close(self):
            self.closed = True

    job = FakeJob()

    def fake_popen(command, **kwargs):
        request_root = Path(kwargs["cwd"])
        meta = json.loads((request_root / command[-3]).read_text(encoding="utf-8"))
        assert meta["wait_for_start"] is True
        observed["gate"] = request_root / "worker.start"
        assert observed["gate"].exists() is False
        (request_root / command[-1]).write_text(
            json.dumps(
                {
                    "status": "ok",
                    "result": {"title": "safe", "text": "isolated result"},
                }
            ),
            encoding="utf-8",
        )
        return FakeProcess()

    monkeypatch.setattr(isolated_document_parser.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        isolated_document_parser,
        "_bind_worker_job",
        lambda _process: (
            observed.__setitem__("bound_before_gate", not observed["gate"].exists())
            or job
        ),
    )

    parsed = parse_document_isolated("docx", _docx_bytes(), "safe.docx", timeout=1)

    assert parsed["text"] == "isolated result"
    assert observed["bound_before_gate"] is True
    assert job.closed is True


@pytest.fixture
def worker_directory(monkeypatch):
    with tempfile.TemporaryDirectory(prefix="defensetracker-parser-") as directory:
        with monkeypatch.context() as scoped:
            scoped.chdir(directory)
            Path("request.json").write_text(
                json.dumps({"kind": "docx", "filename": "safe.docx", "limits": {}}),
                encoding="utf-8",
            )
            Path("input.bin").write_bytes(_docx_bytes("controlled input"))
            yield Path(directory)


@pytest.mark.parametrize("index", [0, 1, 2])
@pytest.mark.parametrize("supplied_path", ["../outside", "nested/file", "C:/outside"])
def test_worker_rejects_paths_before_any_read_or_write(
    worker_directory, index, supplied_path, monkeypatch
):
    def unexpected_read(*_args):
        pytest.fail("invalid worker arguments must not open any input")

    monkeypatch.setattr(isolated_document_parser, "_read_worker_file", unexpected_read)
    arguments = ["request.json", "input.bin", "result.json"]
    arguments[index] = supplied_path
    assert isolated_document_parser.worker_file_entry(*arguments) == 64
    assert not Path("result.json").exists()


def test_worker_rejects_uncontrolled_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert isolated_document_parser.worker_file_entry(
        "request.json", "input.bin", "result.json"
    ) == 64
    assert list(tmp_path.iterdir()) == []


def test_worker_rejects_existing_result_without_overwriting(worker_directory):
    Path("result.json").write_bytes(b"preserve existing file")
    assert isolated_document_parser.worker_file_entry(
        "request.json", "input.bin", "result.json"
    ) == 64
    assert Path("result.json").read_bytes() == b"preserve existing file"


def test_worker_rejects_hardlinked_input(worker_directory):
    os.link("input.bin", "linked-input.bin")
    assert isolated_document_parser.worker_file_entry(
        "request.json", "input.bin", "result.json"
    ) == 3
    result = json.loads(Path("result.json").read_text(encoding="utf-8"))
    assert result["code"] == "DOCUMENT_PARSE_FAILED"


def test_worker_rejects_symlinked_metadata(worker_directory):
    Path("request.json").rename("original-request.json")
    try:
        Path("request.json").symlink_to("original-request.json")
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc.__class__.__name__}")
    assert isolated_document_parser.worker_file_entry(
        "request.json", "input.bin", "result.json"
    ) == 3


def test_upload_filename_cannot_choose_worker_paths():
    result = parse_document_isolated(
        "docx", _docx_bytes("in-memory upload"), "../../outside.docx", timeout=10
    )
    assert result["text"] == "in-memory upload"
