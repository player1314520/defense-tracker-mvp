"""Package an explicitly built unsigned MVP preview; never promote stable assets.

This verifies byte integrity, not publisher identity, malware absence, or cloud
readiness. Build-AndShip owns the clean-source, locked-build, and desktop gates.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath


PREVIEW_TAG = "v9.0.0-mvp.1"
ARCHIVE_NAME = f"DefenseTracker-{PREVIEW_TAG}-windows-x64-portable-UNSIGNED.zip"
COMPANY_NAME = "DefenseTracker Community Edition (Unsigned Development Build)"
REQUIRED_FILES = {"DefenseTracker.exe", "LICENSE", "THIRD_PARTY_NOTICES.md",
                  "THIRD_PARTY_LICENSES/marked-v12.0.0/LICENSE.md",
                  "THIRD_PARTY_LICENSES/DOMPurify-3.2.6/LICENSE",
                  "THIRD_PARTY_LICENSES/supabase-js-v2.95.0/LICENSE",
                  "THIRD_PARTY_LICENSES/esbuild-v0.28.1/LICENSE.md"}
REPOSITORY = "https://github.com/player1314520/defense-tracker-mvp"
SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular(path: Path, *, directory: bool = False) -> None:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
        raise ValueError("Links and Windows reparse points are not allowed")
    check = stat.S_ISDIR if directory else stat.S_ISREG
    if not check(metadata.st_mode):
        raise ValueError("Expected a regular directory or file")


def _absolute(path: Path) -> Path:
    path = path.absolute()
    if ".." in path.parts:
        raise ValueError("Parent traversal is not allowed")
    for parent in reversed(path.parents):
        _regular(parent, directory=True)
    return path


def _relative(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("Invalid payload path")
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or str(parsed) != value:
        raise ValueError("Invalid payload path")
    for part in parsed.parts:
        if (part in {".", ".."} or part.endswith((".", " "))
                or any(ord(char) < 32 or char in '<>:"|?*' for char in part)
                or re.fullmatch(r"(?i)(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\..*)?", part)):
            raise ValueError("Unsafe Windows payload path")
    return value


def _json_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate manifest key")
        result[key] = value
    return result


def verify_candidate(candidate: Path, expected_commit: str) -> tuple[dict, dict[str, Path], str]:
    if not SHA.fullmatch(expected_commit):
        raise ValueError("Expected commit must be an exact lowercase Git SHA")
    candidate = _absolute(candidate)
    _regular(candidate, directory=True)
    files = {}
    folded = set()
    for directory, dirs, names in os.walk(candidate, followlinks=False):
        for name in dirs:
            _regular(Path(directory) / name, directory=True)
        for name in names:
            path = Path(directory) / name
            _regular(path)
            relative = _relative(path.relative_to(candidate).as_posix())
            if relative.casefold() in folded:
                raise ValueError("Case-insensitive duplicate payload path")
            folded.add(relative.casefold())
            files[relative] = path
    if "release-manifest.json" not in files:
        raise ValueError("Preview release manifest is missing")
    manifest_bytes = files["release-manifest.json"].read_bytes()
    manifest = json.loads(manifest_bytes.decode("utf-8-sig"),
                          object_pairs_hook=_json_object)
    if not isinstance(manifest, dict):
        raise ValueError("Preview manifest must be an object")
    artifact = manifest.get("artifact", {})
    if (manifest.get("schema") != 2 or manifest.get("kind") != "unsigned-mvp-preview"
            or artifact != {"channel": "mvp-preview", "stability": "preview",
                            "stable_release_eligible": False, "public_release_eligible": True,
                            "preview_tag": PREVIEW_TAG, "github_prerelease": True}):
        raise ValueError("Only an explicitly built MVP preview manifest is publishable here")
    if (manifest.get("product") != "DefenseTracker"
            or manifest.get("version", {}).get("semantic_version") != "9.0.0"
            or manifest.get("source", {}).get("commit") != expected_commit
            or not SHA.fullmatch(str(manifest.get("source", {}).get("source_tree", "")))
            or manifest.get("signature") != {"authenticode": "NotSigned",
                                            "legal_identity_asserted": False,
                                            "version_info_company_name": COMPANY_NAME}):
        raise ValueError("Preview source, version, or unsigned identity does not match")
    inventory = manifest.get("files")
    if not isinstance(inventory, list) or not inventory:
        raise ValueError("Preview inventory is empty")
    expected = {}
    for entry in inventory:
        if not isinstance(entry, dict):
            raise ValueError("Invalid preview inventory entry")
        name = _relative(entry.get("path"))
        if name.casefold() in expected or name == "release-manifest.json":
            raise ValueError("Duplicate or recursive preview inventory entry")
        expected[name.casefold()] = name
        path = files.get(name)
        if (path is None or type(entry.get("bytes")) is not int
                or entry["bytes"] != path.stat().st_size
                or not SHA256.fullmatch(str(entry.get("sha256", "")))
                or _sha256(path) != entry["sha256"]):
            raise ValueError("Preview payload size or SHA-256 mismatch")
    if set(expected.values()) != set(files) - {"release-manifest.json"}:
        raise ValueError("Preview inventory does not cover every payload file")
    if not REQUIRED_FILES.issubset(files):
        raise ValueError("Preview executable or required license notices are missing")
    return manifest, files, hashlib.sha256(manifest_bytes).hexdigest()


def package_preview(candidate: Path, output: Path, expected_commit: str) -> dict:
    manifest, files, manifest_hash = verify_candidate(candidate, expected_commit)
    candidate = candidate.absolute()
    output = _absolute(output)
    if (os.path.lexists(output) or output.is_relative_to(candidate)
            or candidate.is_relative_to(output)):
        raise ValueError("Output must be a new directory outside the candidate")
    instructions = (
        f"DefenseTracker {PREVIEW_TAG} — 未签名 MVP 预览版\n\n"
        "1. 将整个 ZIP 解压到一个新文件夹；不要直接在压缩包内运行。\n"
        "2. 双击 DefenseTracker/DefenseTracker.exe，保留旁边的 _internal 文件夹。\n"
        "3. 这是未签名程序，Windows 可能显示安全警告；请先核对发布页与 SHA256SUMS。\n"
        "   如果系统或杀毒软件阻止启动，请保留提示并反馈，不要关闭安全防护。\n\n"
        "适用范围：Windows x64，本机单用户，loopback 本地界面。AI 服务需自行配置。\n"
        "此版本没有经过可信发布者签名，不承诺 SmartScreen 信誉；\n"
        "不代表公网 Portal、云同步或多用户生产环境已经上线；\n"
        "AI 生成内容和来源仍需人工复核。\n\n"
        f"源码（AGPL-3.0-only）：{REPOSITORY}/tree/{expected_commit}\n"
        f"构建提交：{expected_commit}\n"
    )
    output.mkdir()
    archive_path = output / ARCHIVE_NAME
    expected_hashes = {entry["path"]: entry["sha256"] for entry in manifest["files"]}
    expected_hashes["release-manifest.json"] = manifest_hash
    with zipfile.ZipFile(archive_path, "x", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=6, allowZip64=True) as archive:
        archive.writestr("START-HERE.txt", instructions.encode("utf-8-sig"))
        for name, path in sorted(files.items()):
            _regular(path)
            digest = hashlib.sha256()
            with path.open("rb") as source, archive.open("DefenseTracker/" + name, "w", force_zip64=True) as target:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
                    target.write(chunk)
            if digest.hexdigest() != expected_hashes[name]:
                raise ValueError("Preview payload changed during packaging")
    with zipfile.ZipFile(archive_path) as archive:
        if archive.testzip() is not None:
            raise ValueError("Preview ZIP CRC verification failed")
    release = {
        "schema": 1, "kind": "unsigned-mvp-preview-release", "tag": PREVIEW_TAG,
        "prerelease": True, "make_latest": False, "signature": "NotSigned",
        "stable_release_eligible": False, "commit": expected_commit,
        "source_url": f"{REPOSITORY}/tree/{expected_commit}",
        "manifest_sha256": expected_hashes["release-manifest.json"],
        "assets": [{"filename": ARCHIVE_NAME, "bytes": archive_path.stat().st_size,
                    "sha256": _sha256(archive_path)}],
    }
    metadata_path = output / "preview-release.json"
    metadata_path.write_text(json.dumps(release, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output / "SHA256SUMS").write_text(
        "".join(f"{_sha256(path)}  {path.name}\n" for path in (archive_path, metadata_path)), encoding="ascii")
    return release


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    try:
        result = package_preview(args.candidate, args.output, args.expected_commit)
    except (ValueError, OSError, TypeError, KeyError) as exc:
        parser.exit(1, f"MVP preview packaging refused: {type(exc).__name__}: {exc}\n")
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
