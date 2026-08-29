from __future__ import annotations

import io
import hashlib
import hmac
import json
import logging
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import auto_start


@pytest.fixture(autouse=True)
def _reset_pinned_ngrok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auto_start, "_ngrok_executable", None, raising=False)
    monkeypatch.setattr(auto_start, "_ngrok_identity", None, raising=False)
    monkeypatch.setattr(auto_start, "_app_supervisor_secret", None, raising=False)
    monkeypatch.setattr(auto_start, "NGROK_DOMAIN", "")
    monkeypatch.setattr(auto_start, "app_proc", None)
    monkeypatch.setattr(auto_start, "ngrok_proc", None)
    monkeypatch.setattr(auto_start, "shutting_down", False)


def _candidate(tmp_path: Path) -> Path:
    install_root = tmp_path / "ngrok install"
    install_root.mkdir()
    executable = install_root / (
        "ngrok.exe" if auto_start.sys.platform == "win32" else "ngrok"
    )
    executable.write_bytes(b"trusted ngrok test fixture")
    executable.chmod(0o700)
    return executable.resolve()


def test_ngrok_resolution_ignores_arbitrary_executable_environment_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trusted = _candidate(tmp_path)
    attacker_selected = tmp_path / "attacker.exe"
    attacker_selected.write_bytes(b"not selected")
    monkeypatch.setenv("NGROK_EXE", str(attacker_selected))
    monkeypatch.setattr(auto_start.shutil, "which", lambda command: str(trusted))

    assert auto_start._pin_ngrok_executable() == trusted
    assert auto_start._verified_ngrok_executable() == trusted


def test_ngrok_resolution_rejects_relative_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(auto_start.shutil, "which", lambda command: "ngrok.exe")

    with pytest.raises(auto_start.NgrokExecutableError, match="absolute"):
        auto_start._pin_ngrok_executable()


@pytest.mark.skipif(auto_start.sys.platform != "win32", reason="Windows UNC policy")
def test_ngrok_resolution_rejects_unc_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        auto_start.shutil,
        "which",
        lambda command: r"\\server\share\ngrok.exe",
    )

    with pytest.raises(auto_start.NgrokExecutableError, match="local filesystem"):
        auto_start._pin_ngrok_executable()


@pytest.mark.skipif(auto_start.sys.platform != "win32", reason="Windows drive policy")
def test_ngrok_resolution_rejects_a_mapped_network_drive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        auto_start.shutil,
        "which",
        lambda command: r"Z:\ngrok.exe",
    )
    monkeypatch.setattr(auto_start, "_windows_path_is_remote", lambda path: True)

    with pytest.raises(auto_start.NgrokExecutableError, match="local filesystem"):
        auto_start._pin_ngrok_executable()


def test_ngrok_reparse_metadata_is_rejected() -> None:
    metadata = SimpleNamespace(
        st_file_attributes=getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )

    assert auto_start._metadata_is_reparse(metadata) is True


def test_ngrok_resolution_rejects_a_reparse_path_component(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = _candidate(tmp_path)
    monkeypatch.setattr(auto_start.shutil, "which", lambda command: str(candidate))
    monkeypatch.setattr(auto_start, "_metadata_is_reparse", lambda metadata: True)

    with pytest.raises(auto_start.NgrokExecutableError, match="reparse point"):
        auto_start._pin_ngrok_executable()


def test_missing_ngrok_fails_closed_before_process_creation(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(auto_start.shutil, "which", lambda command: None)
    monkeypatch.setattr(
        auto_start.subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("Popen reached without a trusted ngrok"),
    )

    with caplog.at_level(logging.ERROR, logger="auto_start"):
        with pytest.raises(auto_start.NgrokExecutableError, match="not found"):
            auto_start.start_ngrok()

    assert "refusing to start" in caplog.text


def test_ngrok_supervisor_refuses_elevated_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(auto_start, "_process_is_elevated", lambda: True)
    monkeypatch.setattr(
        auto_start.shutil,
        "which",
        lambda _command: pytest.fail("PATH was searched from an elevated process"),
    )

    with pytest.raises(auto_start.NgrokExecutableError, match="must not run"):
        auto_start._pin_ngrok_executable()


def test_main_does_not_start_app_when_ngrok_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing_ngrok() -> None:
        raise auto_start.NgrokExecutableError("ngrok executable was not found")

    monkeypatch.setattr(auto_start, "_pin_ngrok_executable", missing_ngrok)
    monkeypatch.setattr(
        auto_start,
        "start_app",
        lambda: pytest.fail("app started before ngrok passed its security gate"),
    )
    monkeypatch.setattr(auto_start.signal, "signal", lambda *args: None)
    monkeypatch.setattr(auto_start, "cleanup", lambda *args: None)

    assert auto_start.main() == 78


def test_ngrok_is_reverified_immediately_before_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trusted = _candidate(tmp_path)
    monkeypatch.setattr(auto_start.shutil, "which", lambda command: str(trusted))
    auto_start._pin_ngrok_executable()
    trusted.write_bytes(b"replacement with a different identity")
    monkeypatch.setattr(
        auto_start.subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("changed executable reached Popen"),
    )

    with pytest.raises(
        auto_start.NgrokExecutableError, match="changed after resolution"
    ):
        auto_start.start_ngrok()


def test_ngrok_swap_during_log_open_is_rejected_before_process_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trusted = _candidate(tmp_path)
    monkeypatch.setattr(auto_start.shutil, "which", lambda command: str(trusted))
    auto_start._pin_ngrok_executable()

    def replace_during_log_open(name: str) -> io.StringIO:
        trusted.write_bytes(b"replacement during validation-to-use window")
        return io.StringIO()

    monkeypatch.setattr(auto_start, "open_log", replace_during_log_open)
    monkeypatch.setattr(
        auto_start.subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("swapped executable reached Popen"),
    )

    with pytest.raises(
        auto_start.NgrokExecutableError, match="changed after resolution"
    ):
        auto_start.start_ngrok()


def test_ngrok_starts_with_the_pinned_absolute_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trusted = _candidate(tmp_path)
    calls: list[list[str]] = []
    options: list[dict[str, object]] = []

    class Process:
        pid = 123

    monkeypatch.setattr(auto_start.shutil, "which", lambda command: str(trusted))
    monkeypatch.setattr(auto_start, "open_log", lambda name: io.StringIO())
    monkeypatch.setattr(
        auto_start.subprocess,
        "Popen",
        lambda argv, **kwargs: (
            calls.append(list(argv)),
            options.append(dict(kwargs)),
            Process(),
        )[-1],
    )

    process = auto_start.start_ngrok()

    assert process.pid == 123
    assert calls == [[str(trusted), "http", "5000"]]
    assert Path(calls[0][0]).is_absolute()
    assert options[0]["executable"] == str(trusted)
    assert options[0]["shell"] is False


def test_ngrok_domain_remains_one_literal_argument(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trusted = _candidate(tmp_path)
    monkeypatch.setattr(auto_start.shutil, "which", lambda command: str(trusted))
    monkeypatch.setattr(auto_start, "NGROK_DOMAIN", "demo.example.test")

    assert auto_start._ngrok_command() == [
        str(trusted),
        "http",
        "5000",
        "--domain",
        "demo.example.test",
    ]


@pytest.mark.parametrize(
    "domain",
    (
        "demo.example.test\r\nINJECTED",
        "https://demo.example.test",
        "demo.example.test/path",
        "UPPER.example.test",
    ),
)
def test_ngrok_domain_rejects_non_dns_or_log_injection_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, domain: str
) -> None:
    trusted = _candidate(tmp_path)
    monkeypatch.setattr(auto_start.shutil, "which", lambda command: str(trusted))
    monkeypatch.setattr(auto_start, "NGROK_DOMAIN", domain)

    with pytest.raises(auto_start.NgrokExecutableError, match="domain"):
        auto_start._ngrok_command()


def test_feishu_batch_uses_the_hardened_supervisor_instead_of_direct_ngrok():
    batch = (Path(__file__).parents[1] / "scripts" / "飞书机器人启动.bat").read_text(
        encoding="utf-8"
    )

    assert "auto_start.py" in batch
    assert "NGROK_EXE" not in batch
    assert 'start "ngrok"' not in batch
    assert "%NGROK_DOMAIN%" not in batch


def test_app_health_probe_requires_the_exact_workspace_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = b"s" * 32
    challenge = "ab" * 16
    expected = {
        "status": "ok",
        "service": "defense-tracker-workspace",
        "version": auto_start.PRODUCT_VERSION.semantic_version,
        "build_commit": "a" * 40,
        "wire_compatibility": "mvp-wire-v1",
        "supervisor_proof": hmac.new(
            secret, challenge.encode("ascii"), hashlib.sha256
        ).hexdigest(),
    }

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _maximum):
            return json.dumps(expected).encode("utf-8")

    monkeypatch.setattr(auto_start, "current_build_commit", lambda: "a" * 40)
    monkeypatch.setattr(auto_start, "_app_supervisor_secret", secret)
    monkeypatch.setattr(auto_start.secrets, "token_hex", lambda _length: challenge)
    monkeypatch.setattr(
        auto_start.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: Response(),
    )

    assert auto_start._app_health_is_ready() is True
    expected["service"] = "unrelated-service"
    assert auto_start._app_health_is_ready() is False


def test_start_app_issues_a_private_per_child_supervisor_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issued = b"x" * 32
    options = {}
    monkeypatch.delenv(auto_start.APP_SUPERVISOR_SECRET_ENV, raising=False)

    class Process:
        pid = 123

    monkeypatch.setattr(auto_start.secrets, "token_bytes", lambda _length: issued)
    monkeypatch.setattr(auto_start, "open_log", lambda _name: io.StringIO())
    monkeypatch.setattr(
        auto_start.subprocess,
        "Popen",
        lambda _argv, **kwargs: (options.update(kwargs), Process())[-1],
    )

    auto_start.start_app()

    assert auto_start._app_supervisor_secret == issued
    assert options["env"][auto_start.APP_SUPERVISOR_SECRET_ENV] == issued.hex()
    assert auto_start.APP_SUPERVISOR_SECRET_ENV not in auto_start.os.environ


def test_main_refuses_to_reuse_an_existing_matching_workspace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    starts = {"app": 0, "ngrok": 0}

    monkeypatch.setattr(
        auto_start, "_pin_ngrok_executable", lambda: Path("C:/ngrok.exe")
    )
    monkeypatch.setattr(auto_start, "_local_app_port_is_occupied", lambda: False)
    monkeypatch.setattr(auto_start, "_app_health_is_ready", lambda: True)
    monkeypatch.setattr(
        auto_start,
        "start_app",
        lambda: starts.__setitem__("app", starts["app"] + 1),
    )

    monkeypatch.setattr(
        auto_start,
        "start_ngrok",
        lambda: starts.__setitem__("ngrok", starts["ngrok"] + 1),
    )
    monkeypatch.setattr(auto_start.signal, "signal", lambda *args: None)
    monkeypatch.setattr(auto_start, "cleanup", lambda *args: None)

    assert auto_start.main() == auto_start.EXIT_APP_PORT_IN_USE
    assert starts == {"app": 0, "ngrok": 0}


def test_main_refuses_an_unrelated_listener_without_probing_or_starting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        auto_start, "_pin_ngrok_executable", lambda: Path("C:/ngrok.exe")
    )
    monkeypatch.setattr(auto_start, "_local_app_port_is_occupied", lambda: True)
    monkeypatch.setattr(
        auto_start,
        "_app_health_is_ready",
        lambda: pytest.fail("occupied port must fail closed before identity probing"),
    )
    monkeypatch.setattr(
        auto_start,
        "start_app",
        lambda: pytest.fail("app started while its port was already occupied"),
    )
    monkeypatch.setattr(
        auto_start,
        "start_ngrok",
        lambda: pytest.fail("ngrok started for an externally owned listener"),
    )
    monkeypatch.setattr(auto_start.signal, "signal", lambda *args: None)
    monkeypatch.setattr(auto_start, "cleanup", lambda *args: None)

    assert auto_start.main() == auto_start.EXIT_APP_PORT_IN_USE


def test_main_starts_ngrok_only_after_its_own_app_child_is_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    starts = {"app": 0, "ngrok": 0}

    class RunningApp:
        @staticmethod
        def poll() -> None:
            return None

    monkeypatch.setattr(
        auto_start, "_pin_ngrok_executable", lambda: Path("C:/ngrok.exe")
    )
    monkeypatch.setattr(auto_start, "_local_app_port_is_occupied", lambda: False)
    monkeypatch.setattr(auto_start, "_app_health_is_ready", lambda: False)

    def start_app() -> RunningApp:
        starts["app"] += 1
        auto_start.app_proc = RunningApp()
        return auto_start.app_proc

    def start_ngrok():
        starts["ngrok"] += 1
        auto_start.shutting_down = True

    monkeypatch.setattr(auto_start, "start_app", start_app)
    monkeypatch.setattr(auto_start, "wait_for_app_ready", lambda: True)
    monkeypatch.setattr(auto_start, "start_ngrok", start_ngrok)
    monkeypatch.setattr(auto_start.signal, "signal", lambda *args: None)
    monkeypatch.setattr(auto_start, "cleanup", lambda *args: None)

    assert auto_start.main() == 0
    assert starts == {"app": 1, "ngrok": 1}


def test_main_does_not_start_ngrok_when_its_app_child_never_becomes_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        auto_start, "_pin_ngrok_executable", lambda: Path("C:/ngrok.exe")
    )
    monkeypatch.setattr(auto_start, "_local_app_port_is_occupied", lambda: False)
    monkeypatch.setattr(auto_start, "_app_health_is_ready", lambda: False)
    monkeypatch.setattr(auto_start, "start_app", lambda: object())
    monkeypatch.setattr(auto_start, "wait_for_app_ready", lambda: False)
    monkeypatch.setattr(
        auto_start,
        "start_ngrok",
        lambda: pytest.fail("ngrok started without a healthy app child"),
    )
    monkeypatch.setattr(auto_start.signal, "signal", lambda *args: None)
    monkeypatch.setattr(auto_start, "cleanup", lambda *args: None)

    assert auto_start.main() == 69


def test_wait_for_app_ready_requires_the_child_to_stay_alive_after_health(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    polls = iter((None, 1, 1))

    class ExitingApp:
        @staticmethod
        def poll():
            return next(polls)

    monkeypatch.setattr(auto_start, "app_proc", ExitingApp())
    monkeypatch.setattr(auto_start, "_app_health_is_ready", lambda: True)
    monkeypatch.setattr(auto_start.time, "sleep", lambda _seconds: None)

    assert auto_start.wait_for_app_ready() is False


def test_supervisor_stops_the_tunnel_when_a_crashed_app_port_is_taken(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    starts = {"app": 0, "ngrok": 0}
    stopped = []
    preexisting = iter((False, True))

    class CrashedApp:
        returncode = 1

        @staticmethod
        def poll() -> int:
            return 1

    class RunningNgrok:
        @staticmethod
        def poll() -> None:
            return None

    def start_app() -> CrashedApp:
        starts["app"] += 1
        auto_start.app_proc = CrashedApp()
        return auto_start.app_proc

    def start_ngrok() -> RunningNgrok:
        starts["ngrok"] += 1
        auto_start.ngrok_proc = RunningNgrok()
        return auto_start.ngrok_proc

    monkeypatch.setattr(
        auto_start, "_pin_ngrok_executable", lambda: Path("C:/ngrok.exe")
    )
    monkeypatch.setattr(auto_start, "_preexisting_local_app", lambda: next(preexisting))
    monkeypatch.setattr(auto_start, "start_app", start_app)
    monkeypatch.setattr(auto_start, "wait_for_app_ready", lambda: True)
    monkeypatch.setattr(auto_start, "start_ngrok", start_ngrok)
    monkeypatch.setattr(auto_start, "_ngrok_still_trusted", lambda: True)
    def stop_proc(proc, name):
        stopped.append((proc, name))
        return True

    monkeypatch.setattr(auto_start, "kill_proc", stop_proc)
    monkeypatch.setattr(auto_start, "_wait_for_app_exit", lambda _timeout: True)
    monkeypatch.setattr(auto_start.signal, "signal", lambda *args: None)
    monkeypatch.setattr(auto_start, "cleanup", lambda *args: None)

    assert auto_start.main() == auto_start.EXIT_APP_PORT_IN_USE
    assert starts == {"app": 1, "ngrok": 1}
    assert len(stopped) == 1
    assert stopped[0][1] == "ngrok"


def test_supervisor_stops_after_the_app_restart_budget_is_exhausted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    starts = {"app": 0, "ngrok": 0}

    class CrashedApp:
        returncode = 1

        @staticmethod
        def poll() -> int:
            return 1

    class RunningNgrok:
        @staticmethod
        def poll() -> None:
            return None

    def start_app() -> CrashedApp:
        starts["app"] += 1
        auto_start.app_proc = CrashedApp()
        return auto_start.app_proc

    def start_ngrok() -> RunningNgrok:
        starts["ngrok"] += 1
        auto_start.ngrok_proc = RunningNgrok()
        return auto_start.ngrok_proc

    monkeypatch.setattr(
        auto_start, "_pin_ngrok_executable", lambda: Path("C:/ngrok.exe")
    )
    monkeypatch.setattr(auto_start, "_local_app_port_is_occupied", lambda: False)
    monkeypatch.setattr(auto_start, "_app_health_is_ready", lambda: False)
    monkeypatch.setattr(auto_start, "start_app", start_app)
    monkeypatch.setattr(auto_start, "wait_for_app_ready", lambda: True)
    monkeypatch.setattr(auto_start, "start_ngrok", start_ngrok)
    monkeypatch.setattr(auto_start, "_ngrok_still_trusted", lambda: True)
    monkeypatch.setattr(auto_start, "kill_proc", lambda proc, name: True)
    monkeypatch.setattr(auto_start, "_wait_for_app_exit", lambda _timeout: True)
    monkeypatch.setattr(auto_start.signal, "signal", lambda *args: None)
    monkeypatch.setattr(auto_start, "cleanup", lambda *args: None)

    assert auto_start.main() == auto_start.EXIT_RESTART_LIMIT
    assert starts == {
        "app": 1 + auto_start.MAX_APP_RESTARTS,
        "ngrok": 1 + auto_start.MAX_APP_RESTARTS,
    }


def test_supervisor_stops_after_the_ngrok_restart_budget_is_exhausted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    starts = {"app": 0, "ngrok": 0}

    class RunningApp:
        @staticmethod
        def poll() -> None:
            return None

    class CrashedNgrok:
        returncode = 1

        @staticmethod
        def poll() -> int:
            return 1

    def start_app() -> RunningApp:
        starts["app"] += 1
        auto_start.app_proc = RunningApp()
        return auto_start.app_proc

    def start_ngrok() -> CrashedNgrok:
        starts["ngrok"] += 1
        auto_start.ngrok_proc = CrashedNgrok()
        return auto_start.ngrok_proc

    monkeypatch.setattr(
        auto_start, "_pin_ngrok_executable", lambda: Path("C:/ngrok.exe")
    )
    monkeypatch.setattr(auto_start, "_local_app_port_is_occupied", lambda: False)
    monkeypatch.setattr(auto_start, "_app_health_is_ready", lambda: False)
    monkeypatch.setattr(auto_start, "start_app", start_app)
    monkeypatch.setattr(auto_start, "wait_for_app_ready", lambda: True)
    monkeypatch.setattr(auto_start, "start_ngrok", start_ngrok)
    monkeypatch.setattr(auto_start, "_ngrok_still_trusted", lambda: True)
    monkeypatch.setattr(auto_start, "_wait_for_app_exit", lambda _timeout: False)
    monkeypatch.setattr(auto_start.signal, "signal", lambda *args: None)
    monkeypatch.setattr(auto_start, "cleanup", lambda *args: None)

    assert auto_start.main() == auto_start.EXIT_RESTART_LIMIT
    assert starts == {"app": 1, "ngrok": 1 + auto_start.MAX_NGROK_RESTARTS}


def test_supervisor_revalidates_ngrok_after_restarting_the_app(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app_starts = 0

    class CrashedApp:
        returncode = 1

        @staticmethod
        def poll() -> int:
            return 1

    class RunningNgrok:
        @staticmethod
        def poll() -> None:
            return None

    def start_app() -> CrashedApp:
        nonlocal app_starts
        app_starts += 1
        auto_start.app_proc = CrashedApp()
        return auto_start.app_proc

    def start_ngrok() -> RunningNgrok:
        auto_start.ngrok_proc = RunningNgrok()
        return auto_start.ngrok_proc

    monkeypatch.setattr(
        auto_start, "_pin_ngrok_executable", lambda: Path("C:/ngrok.exe")
    )
    monkeypatch.setattr(auto_start, "_local_app_port_is_occupied", lambda: False)
    monkeypatch.setattr(auto_start, "_app_health_is_ready", lambda: False)
    monkeypatch.setattr(auto_start, "start_app", start_app)
    monkeypatch.setattr(auto_start, "wait_for_app_ready", lambda: True)
    monkeypatch.setattr(auto_start, "start_ngrok", start_ngrok)
    monkeypatch.setattr(auto_start, "_ngrok_still_trusted", lambda: False)
    monkeypatch.setattr(auto_start, "kill_proc", lambda _proc, _name: True)
    monkeypatch.setattr(auto_start, "_wait_for_app_exit", lambda _timeout: False)
    monkeypatch.setattr(auto_start.signal, "signal", lambda *args: None)
    monkeypatch.setattr(auto_start, "cleanup", lambda *args: None)

    assert auto_start.main() == 70
    assert app_starts == 2
