import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(os.name != "nt", reason="Windows named mutex behavior")
def test_named_mutex_blocks_a_second_desktop_process():
    name = rf"Local\DefenseTracker.Test.{uuid.uuid4().hex}"
    script = (
        "import sys,time; "
        "from desktop_single_instance import try_acquire_desktop_mutex; "
        "m=try_acquire_desktop_mutex(sys.argv[1]); "
        "print('ACQUIRED' if m else 'BLOCKED', flush=True); "
        "time.sleep(30) if m else None"
    )
    first = subprocess.Popen(
        [sys.executable, "-c", script, name],
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert first.stdout is not None
        assert first.stdout.readline().strip() == "ACQUIRED"
        second = subprocess.run(
            [sys.executable, "-c", script, name],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert second.returncode == 0, second.stderr
        assert second.stdout.strip() == "BLOCKED"
    finally:
        first.terminate()
        first.wait(timeout=10)


def test_launcher_acquires_mutex_before_runtime_or_app_imports():
    source = (PROJECT_ROOT / "launcher.py").read_text(encoding="utf-8")
    worker_dispatch = source.index('sys.argv[1] == "--document-parser-worker"')
    acquire = source.index("_acquire_or_exit_single_instance()")
    assert worker_dispatch < source.index("from desktop_single_instance import")
    assert worker_dispatch < acquire
    assert acquire < source.index("from state import")
    assert acquire < source.index("from app import")
