"""Private runtime paths and storage safeguards for WeChat publishing."""

from __future__ import annotations

import csv
from contextlib import closing
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
from typing import Any, Callable, Mapping
import uuid


_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_OWNER_RIGHTS_SID = "S-1-3-4"
_SID_PATTERN = re.compile(r"^S-\d(?:-\d+)+$", re.IGNORECASE)
_REPARSE_POINT_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_PUBLICATION_COLUMNS = (
    "channel",
    "publication_date",
    "edition",
    "content_sha256",
    "source_sha256",
    "state",
    "draft_media_id",
    "publish_id",
    "msg_id",
    "clientmsgid",
    "result_json",
    "operation_owner",
    "operation_kind",
    "lease_until",
    "created_at",
    "updated_at",
)
_PUBLICATION_SCHEMA = {
    "channel": ("TEXT", True, 1),
    "publication_date": ("TEXT", True, 2),
    "edition": ("TEXT", True, 3),
    "content_sha256": ("TEXT", True, 0),
    "source_sha256": ("TEXT", True, 0),
    "state": ("TEXT", True, 0),
    "draft_media_id": ("TEXT", False, 0),
    "publish_id": ("TEXT", False, 0),
    "msg_id": ("TEXT", False, 0),
    "clientmsgid": ("TEXT", False, 0),
    "result_json": ("TEXT", False, 0),
    "operation_owner": ("TEXT", False, 0),
    "operation_kind": ("TEXT", False, 0),
    "lease_until": ("REAL", False, 0),
    "created_at": ("TEXT", True, 0),
    "updated_at": ("TEXT", True, 0),
}
_PROCESS_USER_SID: str | None = None


class RuntimeSecurityError(RuntimeError):
    """A private runtime directory or file could not be secured."""


class LedgerMigrationError(RuntimeError):
    """The legacy publication ledger could not be copied and verified."""


@dataclass(frozen=True)
class WechatRuntimePaths:
    runtime_dir: Path
    vault_path: Path
    ledger_path: Path
    ledger_is_default: bool


def _absolute_path(raw_value: str | os.PathLike[str], *, field: str) -> Path:
    path = Path(raw_value).expanduser()
    if not path.is_absolute():
        raise RuntimeSecurityError(f"{field} must be an absolute path")
    return path


def resolve_runtime_paths(
    environment: Mapping[str, str] | None = None,
    *,
    ledger_override: str | os.PathLike[str] | None = None,
    platform_name: str | None = None,
    home: str | os.PathLike[str] | None = None,
) -> WechatRuntimePaths:
    """Resolve private paths without ever falling back to the source tree."""

    environment = os.environ if environment is None else environment
    platform_name = os.name if platform_name is None else platform_name
    runtime_override = str(environment.get("WECHAT_RUNTIME_DIR", "")).strip()
    if runtime_override:
        runtime_dir = _absolute_path(runtime_override, field="WECHAT_RUNTIME_DIR")
    elif platform_name == "nt":
        local_app_data = str(environment.get("LOCALAPPDATA", "")).strip()
        if not local_app_data and environment is not os.environ:
            local_app_data = str(os.environ.get("LOCALAPPDATA", "")).strip()
        if not local_app_data:
            raise RuntimeSecurityError("LOCALAPPDATA is unavailable")
        runtime_dir = _absolute_path(local_app_data, field="LOCALAPPDATA") / "DefenseTracker" / "wechat"
    else:
        xdg_data_home = str(environment.get("XDG_DATA_HOME", "")).strip()
        if xdg_data_home:
            data_home = _absolute_path(xdg_data_home, field="XDG_DATA_HOME")
        else:
            data_home = Path(home).expanduser() if home is not None else Path.home()
            if not data_home.is_absolute():
                raise RuntimeSecurityError("user home directory is unavailable")
            data_home = data_home / ".local" / "share"
        runtime_dir = data_home / "DefenseTracker" / "wechat"

    explicit_ledger: str | os.PathLike[str] | None = ledger_override
    if explicit_ledger is None:
        configured_ledger = str(environment.get("WECHAT_LEDGER_PATH", "")).strip()
        explicit_ledger = configured_ledger or None
    if explicit_ledger is None:
        ledger_path = runtime_dir / "wechat_publications.sqlite3"
        ledger_is_default = True
    else:
        ledger_path = _absolute_path(explicit_ledger, field="WECHAT_LEDGER_PATH")
        ledger_is_default = False
    return WechatRuntimePaths(
        runtime_dir=runtime_dir,
        vault_path=runtime_dir / ".wechat_mp.vault",
        ledger_path=ledger_path,
        ledger_is_default=ledger_is_default,
    )


def _default_junction_checker(path: Path) -> bool:
    checker = getattr(path, "is_junction", None)
    return bool(checker()) if callable(checker) else False


def reject_windows_reparse_chain(
    path: str | os.PathLike[str],
    *,
    platform_name: str | None = None,
    junction_checker: Callable[[Path], bool] | None = None,
    lstat_func: Callable[[str | os.PathLike[str]], Any] = os.lstat,
) -> None:
    """Reject a Windows reparse point at the target or any ancestor."""

    platform_name = os.name if platform_name is None else platform_name
    if platform_name != "nt":
        return
    checker = junction_checker or _default_junction_checker
    candidate = Path(path)
    while True:
        try:
            if checker(candidate):
                raise RuntimeSecurityError("runtime path contains a junction")
            metadata = lstat_func(candidate)
        except (FileNotFoundError, NotADirectoryError):
            metadata = None
        except RuntimeSecurityError:
            raise
        except OSError as exc:
            raise RuntimeSecurityError("runtime path metadata could not be verified") from exc
        if (
            metadata is not None
            and int(getattr(metadata, "st_file_attributes", 0))
            & _REPARSE_POINT_ATTRIBUTE
        ):
            raise RuntimeSecurityError("runtime path contains a reparse point")
        parent = candidate.parent
        if parent == candidate:
            break
        candidate = parent


def _run_checked(
    runner: Callable[..., Any], argv: list[str], *, input_text: str | None = None
) -> Any:
    try:
        completed = runner(
            argv,
            capture_output=True,
            text=True,
            check=False,
            shell=False,
            input=input_text,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeSecurityError("runtime ACL command failed") from exc
    if int(getattr(completed, "returncode", 1)) != 0:
        raise RuntimeSecurityError("runtime ACL command failed")
    return completed


def _current_user_sid(runner: Callable[..., Any]) -> str:
    global _PROCESS_USER_SID
    if runner is subprocess.run and _PROCESS_USER_SID is not None:
        return _PROCESS_USER_SID
    completed = _run_checked(runner, ["whoami.exe", "/user", "/fo", "csv", "/nh"])
    try:
        rows = list(csv.reader(str(completed.stdout).splitlines()))
        sid = rows[0][1].strip()
    except (IndexError, csv.Error) as exc:
        raise RuntimeSecurityError("current Windows user SID is unavailable") from exc
    if not _SID_PATTERN.fullmatch(sid):
        raise RuntimeSecurityError("current Windows user SID is invalid")
    sid = sid.upper()
    if runner is subprocess.run:
        _PROCESS_USER_SID = sid
    return sid


_ACL_INSPECTION_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$targetKind = [Console]::In.ReadLine()
$targetPath = [Console]::In.ReadLine()
if ($targetKind -eq 'directory') {
    $item = [System.IO.DirectoryInfo]::new([string]$targetPath)
} elseif ($targetKind -eq 'file') {
    $item = [System.IO.FileInfo]::new([string]$targetPath)
} else {
    throw 'unsupported ACL target kind'
}
$acl = $item.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
$rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
$entries = @($rules | ForEach-Object {
    [pscustomobject]@{
        sid = $_.IdentityReference.Value
        type = $_.AccessControlType.ToString()
        rights = $_.FileSystemRights.ToString()
    }
})
[pscustomobject]@{
    protected = [bool]$acl.AreAccessRulesProtected
    entries = $entries
} | ConvertTo-Json -Compress -Depth 4
""".strip()


def _validate_windows_acl(
    path: Path,
    *,
    runner: Callable[..., Any],
    current_user_sid: str | None,
    target_kind: str,
) -> None:
    sid = (current_user_sid or _current_user_sid(runner)).upper()
    if not _SID_PATTERN.fullmatch(sid):
        raise RuntimeSecurityError("current Windows user SID is invalid")
    allowed = {sid, _SYSTEM_SID, _ADMINISTRATORS_SID}
    inspected = _run_checked(
        runner,
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            _ACL_INSPECTION_SCRIPT,
        ],
        input_text=f"{target_kind}\n{path}\n",
    )
    try:
        payload = json.loads(str(inspected.stdout))
        entries = payload["entries"]
        if isinstance(entries, Mapping):
            entries = [entries]
        if (
            not isinstance(entries, list)
            or len(entries) != 3
            or payload.get("protected") is not True
        ):
            raise ValueError("ACL is not protected")
        observed: set[str] = set()
        for entry in entries:
            if not isinstance(entry, Mapping):
                raise ValueError("invalid ACL entry")
            entry_sid = str(entry.get("sid", "")).upper()
            if (
                entry_sid not in allowed
                or str(entry.get("type", "")) != "Allow"
                or str(entry.get("rights", "")) != "FullControl"
            ):
                raise ValueError("unexpected ACL entry")
            observed.add(entry_sid)
        if observed != allowed:
            raise ValueError("required ACL entry is missing")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeSecurityError("runtime ACL validation failed") from exc


def _secure_windows_path(
    path: Path,
    *,
    runner: Callable[..., Any],
    current_user_sid: str | None,
    target_kind: str,
) -> None:
    sid = (current_user_sid or _current_user_sid(runner)).upper()
    if not _SID_PATTERN.fullmatch(sid):
        raise RuntimeSecurityError("current Windows user SID is invalid")
    permission = "(OI)(CI)F" if target_kind == "directory" else "F"
    _run_checked(
        runner,
        [
            "icacls.exe",
            str(path),
            "/inheritance:r",
            "/grant:r",
            f"*{sid}:{permission}",
            f"*{_SYSTEM_SID}:{permission}",
            f"*{_ADMINISTRATORS_SID}:{permission}",
        ],
    )
    # Some Windows parent directories add an explicit OWNER RIGHTS ACE even
    # after inheritance is removed. It is redundant with the named owner and
    # would violate the three-principal allowlist.
    _run_checked(
        runner,
        ["icacls.exe", str(path), "/remove", f"*{_OWNER_RIGHTS_SID}"],
    )
    _validate_windows_acl(
        path,
        runner=runner,
        current_user_sid=sid,
        target_kind=target_kind,
    )


def ensure_secure_directory(
    path: str | os.PathLike[str],
    *,
    platform_name: str | None = None,
    runner: Callable[..., Any] = subprocess.run,
    current_user_sid: str | None = None,
    chmod_func: Callable[[str | os.PathLike[str], int], Any] = os.chmod,
    mode_reader: Callable[[str | os.PathLike[str]], int] | None = None,
    junction_checker: Callable[[Path], bool] | None = None,
    lstat_func: Callable[[str | os.PathLike[str]], Any] = os.lstat,
) -> Path:
    """Create a private directory and verify its effective platform protection."""

    directory = Path(path)
    platform_name = os.name if platform_name is None else platform_name
    reject_windows_reparse_chain(
        directory,
        platform_name=platform_name,
        junction_checker=junction_checker,
        lstat_func=lstat_func,
    )
    if directory.exists() and (not directory.is_dir() or directory.is_symlink()):
        raise RuntimeSecurityError("runtime directory is not a private directory")
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise RuntimeSecurityError("runtime directory could not be created") from exc
    reject_windows_reparse_chain(
        directory,
        platform_name=platform_name,
        junction_checker=junction_checker,
        lstat_func=lstat_func,
    )
    if platform_name == "nt":
        _secure_windows_path(
            directory,
            runner=runner,
            current_user_sid=current_user_sid,
            target_kind="directory",
        )
    else:
        try:
            chmod_func(directory, 0o700)
            mode = (
                mode_reader(directory)
                if mode_reader is not None
                else stat.S_IMODE(directory.stat().st_mode)
            )
        except OSError as exc:
            raise RuntimeSecurityError("runtime directory permissions could not be set") from exc
        if mode != 0o700:
            raise RuntimeSecurityError("runtime directory permissions are not private")
    return directory


def validate_secure_directory(
    path: str | os.PathLike[str],
    *,
    platform_name: str | None = None,
    runner: Callable[..., Any] = subprocess.run,
    current_user_sid: str | None = None,
    mode_reader: Callable[[str | os.PathLike[str]], int] | None = None,
    junction_checker: Callable[[Path], bool] | None = None,
    lstat_func: Callable[[str | os.PathLike[str]], Any] = os.lstat,
) -> Path:
    """Read-only validation for an existing dedicated/private directory."""

    directory = Path(path)
    platform_name = os.name if platform_name is None else platform_name
    reject_windows_reparse_chain(
        directory,
        platform_name=platform_name,
        junction_checker=junction_checker,
        lstat_func=lstat_func,
    )
    if not directory.is_dir() or directory.is_symlink():
        raise RuntimeSecurityError("ledger directory is not a private directory")
    if platform_name == "nt":
        _validate_windows_acl(
            directory,
            runner=runner,
            current_user_sid=current_user_sid,
            target_kind="directory",
        )
    else:
        try:
            mode = (
                mode_reader(directory)
                if mode_reader is not None
                else stat.S_IMODE(directory.stat().st_mode)
            )
        except OSError as exc:
            raise RuntimeSecurityError("ledger directory permissions could not be read") from exc
        if mode != 0o700:
            raise RuntimeSecurityError("ledger directory permissions are not private")
    return directory


def prepare_secure_ledger_directory(
    path: str | os.PathLike[str],
    *,
    platform_name: str | None = None,
    runner: Callable[..., Any] = subprocess.run,
    current_user_sid: str | None = None,
    chmod_func: Callable[[str | os.PathLike[str], int], Any] = os.chmod,
    mode_reader: Callable[[str | os.PathLike[str]], int] | None = None,
    junction_checker: Callable[[Path], bool] | None = None,
    lstat_func: Callable[[str | os.PathLike[str]], Any] = os.lstat,
) -> Path:
    """Validate an existing ledger parent or create one dedicated leaf only."""

    directory = Path(path)
    platform_name = os.name if platform_name is None else platform_name
    reject_windows_reparse_chain(
        directory,
        platform_name=platform_name,
        junction_checker=junction_checker,
        lstat_func=lstat_func,
    )
    if directory.exists():
        return validate_secure_directory(
            directory,
            platform_name=platform_name,
            runner=runner,
            current_user_sid=current_user_sid,
            mode_reader=mode_reader,
            junction_checker=junction_checker,
            lstat_func=lstat_func,
        )
    if not directory.parent.is_dir():
        raise RuntimeSecurityError("ledger directory requires an existing parent")
    try:
        directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    except FileExistsError:
        return validate_secure_directory(
            directory,
            platform_name=platform_name,
            runner=runner,
            current_user_sid=current_user_sid,
            mode_reader=mode_reader,
            junction_checker=junction_checker,
            lstat_func=lstat_func,
        )
    except OSError as exc:
        raise RuntimeSecurityError("ledger directory could not be created") from exc
    return ensure_secure_directory(
        directory,
        platform_name=platform_name,
        runner=runner,
        current_user_sid=current_user_sid,
        chmod_func=chmod_func,
        mode_reader=mode_reader,
        junction_checker=junction_checker,
        lstat_func=lstat_func,
    )


def ensure_private_file(
    path: str | os.PathLike[str],
    *,
    platform_name: str | None = None,
    chmod_func: Callable[[str | os.PathLike[str], int], Any] = os.chmod,
    mode_reader: Callable[[str | os.PathLike[str]], int] | None = None,
    runner: Callable[..., Any] = subprocess.run,
    current_user_sid: str | None = None,
    junction_checker: Callable[[Path], bool] | None = None,
    lstat_func: Callable[[str | os.PathLike[str]], Any] = os.lstat,
) -> Path:
    """Enforce the non-Windows 0600 contract after an atomic/private write."""

    file_path = Path(path)
    platform_name = os.name if platform_name is None else platform_name
    reject_windows_reparse_chain(
        file_path,
        platform_name=platform_name,
        junction_checker=junction_checker,
        lstat_func=lstat_func,
    )
    if not file_path.is_file() or file_path.is_symlink():
        raise RuntimeSecurityError("private runtime file is invalid")
    if platform_name == "nt":
        _secure_windows_path(
            file_path,
            runner=runner,
            current_user_sid=current_user_sid,
            target_kind="file",
        )
    else:
        try:
            chmod_func(file_path, 0o600)
            mode = (
                mode_reader(file_path)
                if mode_reader is not None
                else stat.S_IMODE(file_path.stat().st_mode)
            )
        except OSError as exc:
            raise RuntimeSecurityError("private runtime file permissions could not be set") from exc
        if mode != 0o600:
            raise RuntimeSecurityError("private runtime file permissions are not private")
    return file_path


def _copy_sqlite_database(source: Path, destination: Path) -> None:
    source_uri = source.resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(source_uri, uri=True)) as source_connection:
        source_connection.execute("PRAGMA query_only=ON")
        with closing(sqlite3.connect(destination)) as destination_connection:
            source_connection.backup(destination_connection)


def _publication_rows(path: Path) -> list[tuple[Any, ...]]:
    uri = path.resolve().as_uri() + "?mode=ro"
    try:
        with closing(sqlite3.connect(uri, uri=True)) as connection:
            if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise LedgerMigrationError("publication ledger integrity check failed")
            table_info = connection.execute("PRAGMA table_info(publications)").fetchall()
            columns = {str(row[1]): row for row in table_info}
            if not set(_PUBLICATION_SCHEMA).issubset(columns):
                raise LedgerMigrationError("publication ledger schema is incomplete")
            for name, (expected_type, expected_not_null, expected_pk) in (
                _PUBLICATION_SCHEMA.items()
            ):
                row = columns[name]
                if (
                    str(row[2]).strip().upper() != expected_type
                    or bool(row[3]) is not expected_not_null
                    or int(row[5]) != expected_pk
                ):
                    raise LedgerMigrationError("publication ledger schema is invalid")
            primary_key = sorted(
                (int(row[5]), str(row[1])) for row in table_info if int(row[5]) > 0
            )
            if primary_key != [
                (1, "channel"),
                (2, "publication_date"),
                (3, "edition"),
            ]:
                raise LedgerMigrationError("publication ledger primary key is invalid")
            duplicate = connection.execute(
                """
                SELECT 1 FROM publications
                GROUP BY channel, publication_date, edition
                HAVING COUNT(*) > 1
                LIMIT 1
                """
            ).fetchone()
            if duplicate is not None:
                raise LedgerMigrationError("publication ledger contains duplicate keys")
            selected = ",".join(_PUBLICATION_COLUMNS)
            return connection.execute(
                f"SELECT {selected} FROM publications "
                "ORDER BY channel, publication_date, edition"
            ).fetchall()
    except sqlite3.Error as exc:
        raise LedgerMigrationError("publication ledger verification failed") from exc


def migrate_legacy_ledger(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
    *,
    copier: Callable[[Path, Path], None] = _copy_sqlite_database,
    linker: Callable[[Path, Path], None] = os.link,
) -> bool:
    """Copy one legacy ledger and promote it only after exact row verification."""

    source_path = Path(source)
    destination_path = Path(destination)
    try:
        reject_windows_reparse_chain(source_path)
        reject_windows_reparse_chain(destination_path)
    except RuntimeSecurityError as exc:
        raise LedgerMigrationError("ledger migration path is unsafe") from exc
    if destination_path.exists() or not source_path.is_file():
        return False
    if source_path.resolve() == destination_path.resolve():
        return False
    try:
        prepare_secure_ledger_directory(destination_path.parent)
    except RuntimeSecurityError as exc:
        raise LedgerMigrationError("ledger migration destination is unavailable") from exc
    lock_path = destination_path.with_name(f"{destination_path.name}.migration.lock")
    temporary = destination_path.with_name(
        f"{destination_path.name}.migration-{uuid.uuid4().hex}.tmp"
    )
    lock_owned = False
    destination_created = False
    try:
        try:
            lock_descriptor = os.open(
                lock_path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
        except FileExistsError as exc:
            raise LedgerMigrationError("publication ledger migration is already locked") from exc
        lock_owned = True
        os.close(lock_descriptor)
        ensure_private_file(lock_path)
        if destination_path.exists():
            raise LedgerMigrationError(
                "publication ledger destination appeared during migration"
            )
        copier(source_path, temporary)
        ensure_private_file(temporary)
        source_rows = _publication_rows(source_path)
        copied_rows = _publication_rows(temporary)
        if len(source_rows) != len(copied_rows) or source_rows != copied_rows:
            raise LedgerMigrationError("publication ledger rows do not match")
        if destination_path.exists():
            raise LedgerMigrationError("publication ledger destination appeared during migration")
        try:
            linker(temporary, destination_path)
        except FileExistsError as exc:
            raise LedgerMigrationError(
                "publication ledger destination appeared during migration"
            ) from exc
        destination_created = True
        ensure_private_file(destination_path)
        temporary.unlink()
    except (OSError, sqlite3.Error, RuntimeSecurityError) as exc:
        if destination_created and destination_path.exists():
            destination_path.unlink()
        if temporary.exists():
            temporary.unlink()
        raise LedgerMigrationError("publication ledger migration failed") from exc
    except LedgerMigrationError:
        if destination_created and destination_path.exists():
            destination_path.unlink()
        if temporary.exists():
            temporary.unlink()
        raise
    finally:
        if lock_owned and lock_path.exists():
            lock_path.unlink()
    return True


__all__ = [
    "LedgerMigrationError",
    "RuntimeSecurityError",
    "WechatRuntimePaths",
    "ensure_private_file",
    "ensure_secure_directory",
    "migrate_legacy_ledger",
    "prepare_secure_ledger_directory",
    "reject_windows_reparse_chain",
    "resolve_runtime_paths",
    "validate_secure_directory",
]
