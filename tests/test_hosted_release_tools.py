import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "Initialize-GitHubHostedReleaseTools.ps1"


def _source() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_bootstrap_pins_and_hash_verifies_sdk_and_azure_packages():
    source = _source()

    assert "$sdkPackageVersion = '10.0.26100.4188'" in source
    assert (
        "$sdkPackageSha256 = "
        "'180deb372659029864c10a0c04787833234d64aacd1d2c0661d2c00295d8e022'"
    ) in source
    assert "$artifactSigningVersion = '1.0.128'" in source
    assert (
        "$artifactSigningSha256 = "
        "'74bd7d27e6ce1051409c38d9b46bc8df0400ecd643d51ffbf2ac00869061e40b'"
    ) in source
    assert "api.nuget.org/v3-flatcontainer" in source
    assert "Get-Sha256 -Path $packagePath" in source
    assert "does not match the pinned SHA-256" in source


def test_bootstrap_fails_closed_outside_github_hosted_windows():
    source = _source()

    assert "$env:GITHUB_ACTIONS -cne 'true'" in source
    assert "$env:RUNNER_ENVIRONMENT -cne 'github-hosted'" in source
    assert "$env:RUNNER_OS -cne 'Windows'" in source
    assert "restricted to an ephemeral GitHub-hosted Windows runner" in source
    assert "DEFENSE_TRACKER_EPHEMERAL_RUNNER_MODE" in source
    assert "-Value 'ephemeral'" in source


@pytest.mark.skipif(sys.platform != "win32", reason="Windows PowerShell gate")
def test_non_github_runner_is_rejected_before_any_download(tmp_path):
    github_env = tmp_path / "github-env.txt"
    github_env.write_text("", encoding="utf-8")
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir()
    environment = os.environ.copy()
    environment.update(
        {
            "GITHUB_ACTIONS": "false",
            "RUNNER_ENVIRONMENT": "self-hosted",
            "RUNNER_OS": "Windows",
            "GITHUB_ENV": str(github_env),
            "RUNNER_TEMP": str(runner_temp),
        }
    )

    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SCRIPT),
        ],
        capture_output=True,
        check=False,
        env=environment,
        text=True,
    )

    assert result.returncode != 0
    assert "restricted to an ephemeral GitHub-hosted Windows runner" in (
        result.stdout + result.stderr
    )
    assert not (runner_temp / "defense-tracker-release-tools").exists()


def test_bootstrap_supports_only_the_three_release_modes():
    source = _source()

    assert (
        "[ValidateSet('VerificationOnly', 'AzureArtifactSigning', "
        "'DigiCertKeyLocker')]" in source
    )
    assert "if ($Mode -eq 'AzureArtifactSigning')" in source
    assert "elseif ($Mode -eq 'DigiCertKeyLocker')" in source


def test_bootstrap_exports_every_tool_path_with_observed_hash():
    source = _source()

    for path_name, hash_name in (
        ("DEFENSE_TRACKER_BUILD_PYTHON", "DEFENSE_TRACKER_BUILD_PYTHON_SHA256"),
        ("DEFENSE_TRACKER_SIGNTOOL", "DEFENSE_TRACKER_SIGNTOOL_SHA256"),
        ("DEFENSE_TRACKER_ISCC", "DEFENSE_TRACKER_ISCC_SHA256"),
        ("DEFENSE_TRACKER_7ZIP", "DEFENSE_TRACKER_7ZIP_SHA256"),
        ("DEFENSE_TRACKER_DEFENDER", "DEFENSE_TRACKER_DEFENDER_SHA256"),
    ):
        assert f"-PathVariable '{path_name}'" in source
        assert f"-HashVariable '{hash_name}'" in source
    assert "Get-FileHash -LiteralPath $Path -Algorithm SHA256" in source
    assert "[System.IO.File]::AppendAllText" in source


def test_azure_metadata_is_https_validated_written_privately_and_never_logged():
    source = _source()

    assert "CodeSigningAccountName" in source
    assert "CertificateProfileName" in source
    assert "$endpoint.Scheme -cne 'https'" in source
    assert "[System.IO.File]::WriteAllText(" in source
    assert "($metadata | ConvertTo-Json -Compress)" in source
    assert '$env:GITHUB_RUN_ATTEMPT/$env:GITHUB_SHA"' in source
    assert "$env:GITHUB_SHA -cnotmatch '^[0-9a-f]{40}$'" in source
    assert "Write-Host $metadata" not in source
    assert "Write-Output $metadata" not in source
    assert "ConvertTo-Json -Compress | Write-Host" not in source


def test_script_does_not_echo_signing_secrets_or_dump_environment():
    source = _source()
    host_lines = [line.strip() for line in source.splitlines() if "Write-Host" in line]

    assert host_lines == [
        "Write-Host '[OK] Hash-locked GitHub-hosted Windows release tools are ready.'"
    ]
    for forbidden in (
        "SM_API_KEY",
        "SM_CLIENT_CERT_PASSWORD",
        "AZURE_CLIENT_SECRET",
        "Get-ChildItem Env:",
        "gci env:",
    ):
        assert forbidden not in source


def test_digicert_mode_does_not_decode_or_load_signing_credentials():
    source = _source()

    assert "elseif ($Mode -eq 'DigiCertKeyLocker')" in source
    assert "SM_CLIENT_CERT_FILE_B64" not in source
    assert "FromBase64String" not in source
    assert "Import-PfxCertificate" not in source
