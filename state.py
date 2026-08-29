# -*- coding: utf-8 -*-
"""共享运行时状态与基础常量（从 app.py 纯搬运，零行为变更）。

本模块只依赖标准库，不 import app 或其它项目模块，作为依赖图的叶子，供 app.py 及
各拆分模块（feeds/quality/...）共享同一份可变状态对象。所有可变量
（cache/feed_health/_rate_store）均原地修改、从不重新绑定，因此 `from state import cache`
得到的引用与各模块始终指向同一对象、保持同步。
"""
import json
import os, sys, threading
import hashlib
import shutil
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode


# ── canonical article id：同文异链归一（跟踪参数/协议/www/尾斜杠差异）──
# 三端同步的文章身份基石：书签/已读/收藏跨端对得上，靠的就是这个 id 稳定。
_TRACKING_QUERY_KEYS = {"fbclid", "gclid", "mc_cid", "mc_eid", "igshid", "spm"}


def canonical_article_id(link: str) -> str:
    """规范化 URL 后取 sha1 前 16 位；空链接返回空串。

    只剥公认的跟踪参数（utm_* 等），不动可能承载文章身份的参数（如 ?p=123）。
    """
    link = (link or "").strip()
    if not link:
        return ""
    try:
        s = urlsplit(link)
        scheme = "https" if s.scheme in ("", "http", "https") else s.scheme
        host = s.netloc.lower()
        if host.startswith("www."):
            host = host[4:]
        path = s.path.rstrip("/") or "/"
        query = urlencode([
            (k, v) for k, v in parse_qsl(s.query, keep_blank_values=True)
            if not k.startswith("utm_") and k not in _TRACKING_QUERY_KEYS
        ])
        normalized = urlunsplit((scheme, host, path, query, ""))
    except ValueError:
        normalized = link
    return hashlib.sha1(normalized.encode("utf-8")).hexdigest()[:16]

@dataclass(frozen=True)
class RuntimeLayout:
    """Writable application state, deliberately separate from program files."""

    root: Path
    config: Path
    data: Path
    vault: Path
    logs: Path


def resolve_runtime_layout(
    *,
    frozen: bool,
    platform: str,
    environ: Mapping[str, str],
    project_root: Path,
) -> RuntimeLayout:
    """Resolve runtime paths without filesystem side effects.

    Source checkouts retain their historical project-local layout so existing
    development and tests remain compatible. Packaged applications always use
    a user-writable OS data directory unless DEFENSE_TRACKER_HOME is explicit.
    """
    override = (environ.get("DEFENSE_TRACKER_HOME") or "").strip()
    project_root = Path(project_root).resolve()
    if override:
        root = Path(override).expanduser().resolve()
        return RuntimeLayout(
            root=root,
            config=root / "config",
            data=root / "data",
            vault=root / "vault",
            logs=root / "logs",
        )

    if not frozen:
        return RuntimeLayout(
            root=project_root,
            config=project_root,
            data=project_root / "data",
            vault=project_root / "素材库",
            logs=project_root / "logs",
        )

    if platform == "win32":
        local_app_data = (environ.get("LOCALAPPDATA") or "").strip()
        if not local_app_data:
            raise RuntimeError("LOCALAPPDATA is required for packaged Windows runtime data")
        root = Path(local_app_data).resolve() / "DefenseTracker"
    else:
        xdg_data = (environ.get("XDG_DATA_HOME") or "").strip()
        if xdg_data:
            root = Path(xdg_data).expanduser().resolve() / "DefenseTracker"
        else:
            root = Path(environ.get("HOME", str(Path.home()))).expanduser().resolve()
            root = root / ".local" / "share" / "DefenseTracker"

    return RuntimeLayout(
        root=root,
        config=root / "config",
        data=root / "data",
        vault=root / "vault",
        logs=root / "logs",
    )


def ensure_runtime_layout(layout: RuntimeLayout) -> None:
    for directory in (layout.config, layout.data, layout.vault, layout.logs):
        _require_safe_directory(
            directory,
            create=True,
            private=directory != layout.root,
        )


_LEGACY_CONFIG_FILES = (
    ".access_token",
    ".ai_config.json",
    ".ai_config.key",
    ".feishu_config.json",
    ".supabase_config.json",
    ".supabase_v9_config.json",
    ".search_config.json",
    ".email_config.json",
    ".email_config.key",
)


def _copy_file_if_missing(source: Path, destination: Path) -> bool:
    return _copy_vault_file_atomic(source, destination)


_SUPABASE_CONFIG_FILE = ".supabase_v9_config.json"
_SUPABASE_VAULT_FILES = (
    "supabase-session.vault",
    "supabase-pkce.vault",
)
_SUPABASE_VAULT_MIGRATION_MARKER = ".supabase-vault-migration-v1.complete"
_WINDOWS_REPARSE_POINT = getattr(
    stat,
    "FILE_ATTRIBUTE_REPARSE_POINT",
    0x400,
)


def resolve_supabase_config_path(
    *,
    environ: Mapping[str, str],
    config_dir: Path | str,
) -> Path | None:
    """Select the V9 public config without deriving any secret-state path."""
    candidates: list[Path] = []
    explicit = (environ.get("DEFENSE_TRACKER_SUPABASE_CONFIG") or "").strip()
    if explicit:
        candidates.append(Path(explicit).expanduser())
    candidates.append(Path(config_dir) / _SUPABASE_CONFIG_FILE)
    local_app_data = (environ.get("LOCALAPPDATA") or "").strip()
    if local_app_data:
        candidates.append(
            Path(local_app_data)
            / "DefenseTracker"
            / "config"
            / _SUPABASE_CONFIG_FILE
        )
    for candidate in candidates:
        absolute = Path(os.path.abspath(candidate))
        if absolute.is_file():
            return absolute
    return None


def _unsafe_vault_entry() -> RuntimeError:
    return RuntimeError("unsafe legacy Supabase vault entry")


def _lstat(path: Path):
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def _is_reparse(stat_result) -> bool:
    return bool(
        getattr(stat_result, "st_file_attributes", 0)
        & _WINDOWS_REPARSE_POINT
    )


def _require_safe_directory(
    path: Path, *, create: bool, private: bool = False
) -> bool:
    current = _lstat(path)
    if current is None and create:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        current = _lstat(path)
    if current is None:
        return False
    if (
        stat.S_ISLNK(current.st_mode)
        or _is_reparse(current)
        or not stat.S_ISDIR(current.st_mode)
    ):
        raise _unsafe_vault_entry()
    if private and os.name != "nt":
        os.chmod(path, 0o700)
    return True


def _require_safe_regular_file(path: Path):
    current = _lstat(path)
    if current is None:
        return None
    if (
        stat.S_ISLNK(current.st_mode)
        or _is_reparse(current)
        or not stat.S_ISREG(current.st_mode)
    ):
        raise _unsafe_vault_entry()
    return current


def _copy_vault_file_atomic(source: Path, destination: Path) -> bool:
    _require_safe_directory(
        destination.parent, create=True, private=True
    )
    source_state = _require_safe_regular_file(source)
    if source_state is None:
        return False
    existing = _require_safe_regular_file(destination)
    if existing is not None:
        return False

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".migrating",
        dir=str(destination.parent),
    )
    temporary = Path(temporary_name)
    source_descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        source_descriptor = os.open(source, flags)
        opened_state = os.fstat(source_descriptor)
        if (
            _is_reparse(opened_state)
            or not stat.S_ISREG(opened_state.st_mode)
            or (
                (source_state.st_dev, source_state.st_ino)
                != (opened_state.st_dev, opened_state.st_ino)
            )
        ):
            raise _unsafe_vault_entry()
        with os.fdopen(source_descriptor, "rb", closefd=True) as source_handle:
            source_descriptor = -1
            with os.fdopen(descriptor, "wb", closefd=True) as target_handle:
                descriptor = -1
                shutil.copyfileobj(source_handle, target_handle)
                target_handle.flush()
                os.fsync(target_handle.fileno())
        try:
            os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        try:
            os.link(temporary, destination)
        except FileExistsError:
            _require_safe_regular_file(destination)
            return False
        return True
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _write_private_file_atomic(path: Path, payload: bytes) -> None:
    _require_safe_directory(path.parent, create=True, private=True)
    _require_safe_regular_file(path)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _publish_vault_migration_marker(marker: Path) -> None:
    if _require_safe_regular_file(marker) is not None:
        return
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{marker.name}.",
        suffix=".migrating",
        dir=str(marker.parent),
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(b"v1\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        try:
            os.link(temporary, marker)
        except FileExistsError:
            _require_safe_regular_file(marker)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _migrate_legacy_supabase_vault(
    selected_config: Path | str,
    canonical_vault: Path | str,
) -> dict[str, int]:
    """Copy only the two files written through the old config-derived vault."""
    config_path = Path(selected_config)
    legacy_vault = config_path.parent.parent / "vault"
    destination_vault = Path(canonical_vault)
    _require_safe_directory(
        destination_vault, create=True, private=True
    )
    if os.path.normcase(os.path.abspath(legacy_vault)) == os.path.normcase(
        os.path.abspath(destination_vault)
    ):
        for filename in _SUPABASE_VAULT_FILES:
            _require_safe_regular_file(destination_vault / filename)
        return {"copied": 0, "skipped_existing": 0}
    marker = destination_vault / _SUPABASE_VAULT_MIGRATION_MARKER
    if _require_safe_regular_file(marker) is not None:
        skipped = sum(
            _require_safe_regular_file(destination_vault / filename) is not None
            for filename in _SUPABASE_VAULT_FILES
        )
        return {"copied": 0, "skipped_existing": skipped}
    if not _require_safe_directory(legacy_vault, create=False):
        return {"copied": 0, "skipped_existing": 0}

    copied = 0
    skipped = 0
    found = False
    for filename in _SUPABASE_VAULT_FILES:
        source = legacy_vault / filename
        if _lstat(source) is None:
            continue
        found = True
        if _copy_vault_file_atomic(source, destination_vault / filename):
            copied += 1
        else:
            skipped += 1
    if found:
        _publish_vault_migration_marker(marker)
    return {"copied": copied, "skipped_existing": skipped}


def migrate_legacy_supabase_vault(
    selected_config: Path | str,
    canonical_vault: Path | str,
) -> dict[str, int]:
    """Run the narrow migration without exposing private paths in errors."""
    try:
        return _migrate_legacy_supabase_vault(
            selected_config,
            canonical_vault,
        )
    except OSError:
        raise RuntimeError("Supabase vault migration failed") from None


def migrate_legacy_runtime(legacy_root: Path, layout: RuntimeLayout) -> dict:
    """Copy legacy EXE-adjacent state once, never overwrite, never log values."""
    legacy_root = Path(legacy_root).resolve()
    ensure_runtime_layout(layout)
    copied: list[str] = []
    skipped: list[str] = []

    master_key_destination = layout.vault / ".v9_local_master.key"
    for source in (
        layout.config / ".v9_local_master.key",
        legacy_root / "config" / ".v9_local_master.key",
        legacy_root / ".v9_local_master.key",
    ):
        if not source.is_file():
            continue
        relative = "vault/.v9_local_master.key"
        if _copy_file_if_missing(source, master_key_destination):
            copied.append(relative)
        else:
            skipped.append(relative)
        break

    for filename in _LEGACY_CONFIG_FILES:
        source = legacy_root / filename
        if not source.is_file():
            continue
        destination = layout.config / filename
        relative = f"config/{filename}"
        if _copy_file_if_missing(source, destination):
            copied.append(relative)
        else:
            skipped.append(relative)

    for source_dir, destination_dir, label in (
        (legacy_root / "data", layout.data, "data"),
        (legacy_root / "素材库", layout.vault, "vault"),
    ):
        if not _require_safe_directory(source_dir, create=False):
            continue
        for source in source_dir.rglob("*"):
            if not source.is_file() or source.name.startswith("~$"):
                continue
            relative_path = source.relative_to(source_dir)
            relative = f"{label}/{relative_path.as_posix()}"
            if _copy_file_if_missing(source, destination_dir / relative_path):
                copied.append(relative)
            else:
                skipped.append(relative)

    manifest_path = layout.logs / "legacy-migration.json"
    manifest = {
        "schema": 2,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "source_kind": "legacy-runtime",
        "copied": copied,
        "skipped_existing": skipped,
    }
    _write_private_file_atomic(
        manifest_path,
        (
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
        ).encode("utf-8"),
    )
    return {
        "copied": len(copied),
        "skipped": len(skipped),
        "manifest": str(manifest_path),
    }


_PROJECT_ROOT = Path(__file__).resolve().parent
RUNTIME_LAYOUT = resolve_runtime_layout(
    frozen=bool(getattr(sys, "frozen", False)),
    platform=sys.platform,
    environ=os.environ,
    project_root=_PROJECT_ROOT,
)
RUNTIME_DIR = RUNTIME_LAYOUT.root
CONFIG_DIR = RUNTIME_LAYOUT.config
DATA_DIR = RUNTIME_LAYOUT.data
VAULT_DIR = RUNTIME_LAYOUT.vault
LOG_DIR = RUNTIME_LAYOUT.logs

# Backwards-compatible alias while persistence call sites migrate by subsystem.
_RUNTIME_BASE_DIR = str(RUNTIME_DIR)

# 简单速率限制：{ip: [timestamp,...]}
_rate_store: dict = {}
_rate_lock  = threading.Lock()

# ── 缓存 & 抓取共享状态
cache = {"news": [], "last_update": None, "fetch_errors": [], "fetch_stats": {}}
# 订阅源健康档案：{name: {ok_cnt, fail_cnt, last_ok_ts, last_err, fail_streak}}
feed_health = {}
feed_health_lock = threading.Lock()
cache_lock = threading.Lock()
NEWS_DAYS = 3
NEWS_CACHE_TTL_HOURS = 24
NEWS_CACHE_MAX = 500
