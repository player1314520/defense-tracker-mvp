# -*- coding: utf-8 -*-
"""Validated access to DefenseTracker's single product-version source."""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any


_SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_WINDOWS_VERSION_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True, slots=True)
class ProductVersion:
    schema: int
    product_name: str
    semantic_version: str
    windows_file_version: str
    display_version: str
    release_tag: str
    release_baseline: str

    @property
    def windows_file_version_tuple(self) -> tuple[int, int, int, int]:
        return tuple(int(part) for part in self.windows_file_version.split("."))  # type: ignore[return-value]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class BuildMetadata:
    schema: int
    commit: str
    source_tree: str
    source_date_epoch_utc: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _default_version_file() -> Path:
    frozen_root = getattr(sys, "_MEIPASS", None)
    if frozen_root:
        return Path(frozen_root) / "version.json"
    return Path(__file__).resolve().with_name("version.json")


def _default_build_metadata_file() -> Path:
    frozen_root = getattr(sys, "_MEIPASS", None)
    if frozen_root:
        return Path(frozen_root) / "build-metadata.json"
    return Path(__file__).resolve().with_name("build-metadata.json")


@lru_cache(maxsize=4)
def load_product_version(path: str | Path | None = None) -> ProductVersion:
    version_path = Path(path).resolve() if path is not None else _default_version_file()
    try:
        payload = json.loads(version_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Unable to load product version metadata: {version_path}") from exc
    if not isinstance(payload, dict):
        raise ValueError("version.json must contain one JSON object")

    required = {
        "schema",
        "product_name",
        "semantic_version",
        "windows_file_version",
        "display_version",
        "release_tag",
        "release_baseline",
    }
    missing = sorted(required.difference(payload))
    unexpected = sorted(set(payload).difference(required))
    if missing or unexpected:
        raise ValueError(
            f"version.json keys differ from the contract (missing={missing}, unexpected={unexpected})"
        )

    version = ProductVersion(**payload)
    if version.schema != 1:
        raise ValueError("Unsupported version.json schema")
    if not version.product_name or len(version.product_name) > 80:
        raise ValueError("product_name must be a short non-empty string")
    semantic_match = _SEMVER_RE.fullmatch(version.semantic_version)
    windows_match = _WINDOWS_VERSION_RE.fullmatch(version.windows_file_version)
    if semantic_match is None or windows_match is None:
        raise ValueError("Only stable numeric semantic and Windows versions are supported")
    semantic_parts = tuple(int(part) for part in semantic_match.groups())
    windows_parts = tuple(int(part) for part in windows_match.groups())
    if windows_parts != (*semantic_parts, 0):
        raise ValueError("windows_file_version must equal semantic_version plus a zero revision")
    if version.display_version != f"V{semantic_parts[0]}":
        raise ValueError("display_version must equal V plus the semantic major version")
    if version.release_tag != f"v{version.semantic_version}":
        raise ValueError("release_tag must equal v plus semantic_version")
    if _SHA_RE.fullmatch(version.release_baseline) is None:
        raise ValueError("release_baseline must be a full lowercase Git SHA")
    return version


PRODUCT_VERSION = load_product_version()


@lru_cache(maxsize=4)
def load_build_metadata(path: str | Path | None = None) -> BuildMetadata | None:
    metadata_path = (
        Path(path).resolve() if path is not None else _default_build_metadata_file()
    )
    if not metadata_path.is_file():
        return None
    try:
        payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Unable to load build metadata: {metadata_path}") from exc
    if not isinstance(payload, dict):
        raise ValueError("build-metadata.json must contain one JSON object")
    common = {"schema", "commit", "source_tree"}
    timestamp_key = "built_at_utc" if payload.get("schema") == 1 else "source_date_epoch_utc"
    required = common | {timestamp_key}
    allowed = required | {"context_files"}
    if not required.issubset(payload) or not set(payload).issubset(allowed):
        raise ValueError("build-metadata.json keys differ from the contract")
    if "context_files" in payload and not isinstance(payload["context_files"], list):
        raise ValueError("build metadata context_files must be a list")
    normalized = {key: payload[key] for key in common}
    normalized["source_date_epoch_utc"] = payload[timestamp_key]
    metadata = BuildMetadata(**normalized)
    if metadata.schema not in {1, 2}:
        raise ValueError("Unsupported build-metadata.json schema")
    if _SHA_RE.fullmatch(metadata.commit) is None:
        raise ValueError("build commit must be a full lowercase Git SHA")
    if _SHA_RE.fullmatch(metadata.source_tree) is None:
        raise ValueError("source tree must be a full lowercase Git object ID")
    if not metadata.source_date_epoch_utc.endswith("Z"):
        raise ValueError("source_date_epoch_utc must be a UTC timestamp ending in Z")
    return metadata


def current_build_commit() -> str:
    configured = os.environ.get("DEFENSE_TRACKER_BUILD_COMMIT", "").strip()
    if configured:
        if _SHA_RE.fullmatch(configured) is None:
            raise ValueError("DEFENSE_TRACKER_BUILD_COMMIT must be a full lowercase Git SHA")
        return configured
    metadata = load_build_metadata()
    return metadata.commit if metadata is not None else "development"


def current_build_id() -> str:
    """Return one display-safe identity derived from canonical build metadata."""
    metadata = load_build_metadata()
    if metadata is None:
        return f"{PRODUCT_VERSION.semantic_version}+development"
    timestamp = re.sub(r"[^0-9]", "", metadata.source_date_epoch_utc)[:14]
    return (
        f"{PRODUCT_VERSION.semantic_version}+{metadata.commit[:12]}."
        f"{metadata.source_tree[:12]}.{timestamp or 'unknown'}Z"
    )


if __name__ == "__main__":
    print(json.dumps(PRODUCT_VERSION.as_dict(), ensure_ascii=False, sort_keys=True))
