from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from scripts.package_mvp_preview import ARCHIVE_NAME, COMPANY_NAME, PREVIEW_TAG, REQUIRED_FILES, package_preview


COMMIT = "4" * 40


@pytest.fixture
def candidate(tmp_path):
    root = tmp_path / "candidate"
    root.mkdir()
    for name in REQUIRED_FILES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"test-required-file")
    for name, data in {"DefenseTracker.exe": b"test-built-executable",
                       "LICENSE": b"AGPL-3.0-only",
                       "THIRD_PARTY_NOTICES.md": b"Third-party notices"}.items():
        (root / name).write_bytes(data)
    manifest = {
        "schema": 2, "kind": "unsigned-mvp-preview", "product": "DefenseTracker",
        "version": {"semantic_version": "9.0.0"},
        "source": {"commit": COMMIT, "source_tree": "3" * 40},
        "artifact": {"channel": "mvp-preview", "stability": "preview",
                     "stable_release_eligible": False, "public_release_eligible": True,
                     "preview_tag": PREVIEW_TAG, "github_prerelease": True},
        "signature": {"authenticode": "NotSigned", "legal_identity_asserted": False,
                      "version_info_company_name": COMPANY_NAME},
        "files": [{"path": path.relative_to(root).as_posix(), "bytes": path.stat().st_size,
                   "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                  for path in sorted(root.rglob("*")) if path.is_file()],
    }
    (root / "release-manifest.json").write_text(json.dumps(manifest), encoding="utf-8-sig")
    return root


def _change_manifest(candidate, change):
    path = candidate / "release-manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8-sig"))
    change(manifest)
    path.write_text(json.dumps(manifest), encoding="utf-8")


def test_packages_explicit_preview_with_byte_verified_downloads(candidate, tmp_path):
    output = tmp_path / "downloads"
    result = package_preview(candidate, output, COMMIT)
    assert result["prerelease"] is True
    assert result["make_latest"] is False
    assert result["stable_release_eligible"] is False
    assert result["tag"] == PREVIEW_TAG
    assert result["signature"] == "NotSigned"
    with zipfile.ZipFile(output / ARCHIVE_NAME) as archive:
        assert archive.testzip() is None
        assert archive.read("DefenseTracker/DefenseTracker.exe") == (candidate / "DefenseTracker.exe").read_bytes()
        assert "未签名 MVP 预览版" in archive.read("START-HERE.txt").decode("utf-8-sig")
        assert "DefenseTracker/LICENSE" in archive.namelist()
    for line in (output / "SHA256SUMS").read_text().splitlines():
        digest, filename = line.split("  ")
        assert hashlib.sha256((output / filename).read_bytes()).hexdigest() == digest


@pytest.mark.parametrize("change", [
    lambda m: m.update(kind="unsigned-development-candidate"),
    lambda m: m.update(kind="stable-release"),
    lambda m: m["artifact"].update(channel="development", public_release_eligible=False),
    lambda m: m["artifact"].update(stable_release_eligible=True),
    lambda m: m["artifact"].update(preview_tag="v9.0.0"),
    lambda m: m["artifact"].update(github_prerelease=False),
    lambda m: m["source"].update(commit="5" * 40),
    lambda m: m["signature"].update(authenticode="Valid"),
])
def test_refuses_other_channels_or_commit(candidate, tmp_path, change):
    _change_manifest(candidate, change)
    with pytest.raises(ValueError):
        package_preview(candidate, tmp_path / "downloads", COMMIT)
    assert not (tmp_path / "downloads").exists()


def test_tampered_or_unlisted_payload_refused(candidate, tmp_path):
    original = (candidate / "DefenseTracker.exe").read_bytes()
    (candidate / "DefenseTracker.exe").write_bytes(b"x" * len(original))
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        package_preview(candidate, tmp_path / "downloads", COMMIT)
    (candidate / "DefenseTracker.exe").write_bytes(original)
    (candidate / "private.txt").write_text("extra payload", encoding="utf-8")
    with pytest.raises(ValueError, match="every payload"):
        package_preview(candidate, tmp_path / "downloads", COMMIT)


@pytest.mark.parametrize("path", ["../outside", "/absolute", "C:/absolute", "x\\y", "./x", "con.txt", "x/../y"])
def test_refuses_unsafe_archive_paths(candidate, tmp_path, path):
    _change_manifest(candidate, lambda m: m["files"][0].update(path=path))
    with pytest.raises(ValueError):
        package_preview(candidate, tmp_path / "downloads", COMMIT)


def test_output_is_new_and_outside_payload(candidate, tmp_path):
    existing = tmp_path / "existing"
    existing.mkdir()
    for output in (candidate / "downloads", existing):
        with pytest.raises(ValueError, match="new directory"):
            package_preview(candidate, output, COMMIT)


def test_refuses_symlink_payload(candidate, tmp_path):
    target = tmp_path / "target"
    target.write_text("outside", encoding="utf-8")
    try:
        os.symlink(target, candidate / "link")
    except OSError:
        pytest.skip("Symlink creation is not available")
    with pytest.raises(ValueError, match="Links"):
        package_preview(candidate, tmp_path / "downloads", COMMIT)


def test_preview_build_uses_existing_gates_and_separate_output():
    source = (Path(__file__).resolve().parents[1] / "scripts/Build-AndShip.ps1").read_text(encoding="utf-8-sig")
    assert "[switch]$UnsignedMvpPreview" in source
    assert "Unsigned MVP preview cannot be combined" in source
    assert "Assert-CleanReleaseCommit $projectRoot $ExpectedReleaseSha" in source
    assert "Invoke-DesktopSmokeTest $stagedExe" in source
    assert "mvp-preview\\v9.0.0-mvp.1" in source
    assert "-MvpPreview:$UnsignedMvpPreview" in source
    assert "scripts\\package_mvp_preview.py" in source


@pytest.mark.skipif(os.name != "nt", reason="Build manifest writer is Windows-only")
def test_actual_powershell_preview_manifest_is_accepted(candidate, tmp_path):
    source = (Path(__file__).resolve().parents[1] / "scripts/Build-AndShip.ps1").read_text(encoding="utf-8-sig")
    start = source.index("function Write-DevelopmentBuildManifest")
    function = source[start:source.index("\n$projectRoot", start)]
    (candidate / "release-manifest.json").unlink()
    script = tmp_path / "preview-contract.ps1"
    script.write_text(
        "$ErrorActionPreference = 'Stop'\nSet-StrictMode -Version Latest\n"
        "function Get-Sha256 { param([string]$Path) "
        "return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }\n"
        + function + "\n"
        + "$version = [pscustomobject]@{ product_name = 'DefenseTracker'; "
        "semantic_version = '9.0.0'; release_baseline = ('5' * 40) }\n"
        + "$gitFacts = [pscustomobject]@{ commit = ('4' * 40); tree = ('3' * 40) }\n"
        + "Write-DevelopmentBuildManifest '" + str(candidate).replace("'", "''")
        + f"' $version $gitFacts '{COMPANY_NAME}' -MvpPreview\n",
        encoding="utf-8-sig",
    )
    result = subprocess.run([shutil.which("pwsh") or shutil.which("powershell.exe"), "-NoProfile", "-File", str(script)],
                            capture_output=True, text=True, errors="replace", check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    release = package_preview(candidate, tmp_path / "downloads", COMMIT)
    assert release["tag"] == PREVIEW_TAG
