import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from product_version import PRODUCT_VERSION
from scripts.generate_windows_version_info import render_version_info


ROOT = Path(__file__).resolve().parents[1]
UNSIGNED_DEVELOPMENT_COMPANY_NAME = (
    "DefenseTracker Community Edition (Unsigned Development Build)"
)


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8-sig")


def _powershell() -> str:
    executable = shutil.which("pwsh") or shutil.which("powershell")
    if executable is None:
        pytest.skip("PowerShell is unavailable")
    return executable


def _run_build_gate(*extra: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.pop("DEFENSE_TRACKER_PUBLISHER", None)
    return subprocess.run(
        [
            _powershell(),
            "-NoProfile",
            "-File",
            str(ROOT / "scripts" / "Build-AndShip.ps1"),
            "-ExpectedReleaseSha",
            "0" * 40,
            *extra,
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def test_unsigned_development_version_info_is_explicitly_non_publisher():
    rendered = render_version_info(
        PRODUCT_VERSION,
        UNSIGNED_DEVELOPMENT_COMPANY_NAME,
        unsigned_development=True,
    )

    assert UNSIGNED_DEVELOPMENT_COMPANY_NAME in rendered
    assert "Unsigned development build; no publisher identity asserted" in rendered
    assert (
        f"Copyright (c) 2026 {UNSIGNED_DEVELOPMENT_COMPANY_NAME}" not in rendered
    )


def test_unsigned_development_version_info_rejects_a_publisher_identity():
    with pytest.raises(ValueError, match="fixed non-identity CompanyName"):
        render_version_info(
            PRODUCT_VERSION,
            "Example Legal Publisher",
            unsigned_development=True,
        )


def test_signed_version_info_rejects_the_unsigned_development_label():
    with pytest.raises(ValueError, match="cannot be used for signed builds"):
        render_version_info(
            PRODUCT_VERSION,
            UNSIGNED_DEVELOPMENT_COMPANY_NAME,
        )


def test_unsigned_entrypoint_advances_without_a_publisher():
    result = _run_build_gate()
    combined = result.stdout + result.stderr

    assert result.returncode != 0
    assert "DEFENSE_TRACKER_PUBLISHER must be the verified legal Publisher" not in combined
    assert (
        "Release requires a clean Git worktree" in combined
        or "HEAD differs from ExpectedReleaseSha" in combined
    )


def test_signed_entrypoint_fails_closed_without_a_verified_publisher():
    result = _run_build_gate("-RequireSignedInstaller", "-CandidateOnly")
    combined = result.stdout + result.stderr

    assert result.returncode != 0
    assert (
        "DEFENSE_TRACKER_PUBLISHER must be the verified legal Publisher" in combined
    )


def test_build_gate_separates_unsigned_company_label_from_signed_publisher():
    source = _read("scripts/Build-AndShip.ps1")

    assert UNSIGNED_DEVELOPMENT_COMPANY_NAME in source
    assert (
        "if ($RequireSignedInstaller -and "
        "[string]::IsNullOrWhiteSpace($PublisherName))" in source
    )
    assert (
        'throw "DEFENSE_TRACKER_PUBLISHER must be the verified legal Publisher; '
        'it is never inferred."' in source
    )
    assert '$buildKind = "unsigned-development-candidate"' in source
    assert '$buildKind = "signed-release-candidate"' in source
    assert "DEFENSE_TRACKER_VERSION_INFO_COMPANY_NAME" in source
    assert "DEFENSE_TRACKER_BUILD_KIND" in source
    assert "Assert-VersionInfo $stagedExe $version $versionInfoCompanyName" in source
    assert "Assert-VersionInfo $stagedExe $version $PublisherName" not in source

    manifest_start = source.index("function Write-DevelopmentBuildManifest")
    manifest_end = source.index("\n$projectRoot", manifest_start)
    manifest = source[manifest_start:manifest_end]
    assert 'kind = "unsigned-development-candidate"' in manifest
    assert 'channel = "development"' in manifest
    assert 'authenticode = "NotSigned"' in manifest
    assert "stable_release_eligible = $false" in manifest
    assert "public_release_eligible = $false" in manifest
    assert "version_info_company_name = $VersionInfoCompanyName" in manifest
    assert "publisher =" not in manifest.lower()
    assert 'kind = "stable-release"' not in manifest
    assert "Get-AuthenticodeSignature -LiteralPath $stagedExe" in source
    assert "Unsigned development executable must be Authenticode NotSigned" in source
    assert source.index("Get-AuthenticodeSignature -LiteralPath $stagedExe") < source.index(
        "Write-DevelopmentBuildManifest $stagingRoot"
    )


@pytest.mark.skipif(os.name != "nt", reason="development packager is Windows-only")
def test_development_manifest_runtime_contract(tmp_path):
    source = _read("scripts/Build-AndShip.ps1")
    function_start = source.index("function Write-DevelopmentBuildManifest")
    function_end = source.index("\n$projectRoot", function_start)
    function_source = source[function_start:function_end]
    candidate = tmp_path / "candidate"
    script = tmp_path / "manifest-contract.ps1"
    quoted_candidate = str(candidate).replace("'", "''")
    script.write_text(
        "$ErrorActionPreference = 'Stop'\n"
        "function Get-Sha256 { param([string]$Path) "
        "return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }\n"
        + function_source
        + "\n"
        + f"$root = '{quoted_candidate}'\n"
        + "New-Item -ItemType Directory -Path $root | Out-Null\n"
        + "[System.IO.File]::WriteAllText((Join-Path $root 'DefenseTracker.exe'), 'fixture')\n"
        + "$version = [pscustomobject]@{ product_name = 'DefenseTracker'; "
        "semantic_version = '9.0.0'; release_baseline = ('5' * 40) }\n"
        + "$gitFacts = [pscustomobject]@{ commit = ('4' * 40); tree = ('3' * 40) }\n"
        + f"Write-DevelopmentBuildManifest $root $version $gitFacts '{UNSIGNED_DEVELOPMENT_COMPANY_NAME}'\n"
        + "Get-Content -LiteralPath (Join-Path $root 'release-manifest.json') -Raw\n",
        encoding="utf-8-sig",
    )
    result = subprocess.run(
        [_powershell(), "-NoProfile", "-File", str(script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    manifest = json.loads(result.stdout)
    assert manifest["kind"] == "unsigned-development-candidate"
    assert "release" not in manifest
    assert manifest["artifact"] == {
        "channel": "development",
        "stability": "development",
        "stable_release_eligible": False,
        "public_release_eligible": False,
    }
    assert manifest["signature"] == {
        "authenticode": "NotSigned",
        "legal_identity_asserted": False,
        "version_info_company_name": UNSIGNED_DEVELOPMENT_COMPANY_NAME,
    }


def test_builder_requires_explicit_build_kind_and_version_info_company_name():
    source = _read("scripts/build_app.py")

    assert '"DEFENSE_TRACKER_VERSION_INFO_COMPANY_NAME"' in source
    assert '"DEFENSE_TRACKER_BUILD_KIND"' in source
    assert '_required_build_value("DEFENSE_TRACKER_PUBLISHER")' not in source
    assert "unsigned_development=unsigned_development" in source
    assert "unsigned-development-candidate" in source
    assert "signed-release-candidate" in source


def test_unsigned_development_workflow_is_ephemeral_read_only_and_main_bound():
    source = _read(".github/workflows/v9-development-candidate.yml")

    assert "workflow_dispatch:" in source
    assert "contents: read" in source
    for forbidden_permission in (
        "contents: write",
        "packages: write",
        "id-token: write",
        "attestations: write",
    ):
        assert forbidden_permission not in source
    assert "if: github.ref == 'refs/heads/main'" in source
    assert "git ls-remote --exit-code origin refs/heads/main" in source
    assert 'test "${GITHUB_SHA}" = "${RELEASE_SHA}"' in source
    assert 'test "${GITHUB_WORKFLOW_SHA}" = "${RELEASE_SHA}"' in source
    assert "persist-credentials: false" in source
    assert "ref: ${{ github.sha }}" in source
    assert "fetch-depth: 0" in source
    assert "ref: ${{ inputs.release_sha }}" not in source

    assert (
        "actions/checkout@11d5960a326750d5838078e36cf38b85af677262" in source
    )
    assert (
        "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065" in source
    )
    assert 'python-version: "3.11"' in source
    assert "Prepare-BuildEnv.ps1" in source
    assert "Build-AndShip.ps1" in source
    assert "-RequireSignedInstaller" not in source
    assert "requirements.build.lock" in source
    assert "requirements.bootstrap.lock" in source

    assert source.lower().count("unsigned-development") >= 6
    assert "Binary publication: disabled (public repository)" in source
    assert "UNSIGNED_DEVELOPMENT_VERIFIED" in source
    assert "NotSigned" in source
    for forbidden_operation in (
        "actions/upload-artifact",
        "private unsigned-development",
        "Compress-Archive",
        "gh release",
        "git push",
        "refs/tags/",
        "actions/create-release",
        "softprops/action-gh-release",
    ):
        assert forbidden_operation not in source
