# -*- coding: utf-8 -*-
import json
from datetime import timezone
from pathlib import Path
import shutil
import subprocess

import pytest

from product_version import load_build_metadata
from scripts.package_release_assets import parse_utc


ROOT = Path(__file__).resolve().parents[1]


def _powershell() -> str:
    executable = shutil.which("pwsh") or shutil.which("powershell")
    if executable is None:
        pytest.skip("PowerShell is unavailable")
    return executable


def test_release_layout_uses_tag_and_never_guesses_legacy_archive_identity():
    source = (ROOT / "scripts" / "Build-AndShip.ps1").read_text(encoding="utf-8")
    assert '("releases\\" + $version.release_tag)' in source
    assert '("candidates\\" + $version.release_tag)' in source
    assert "DEFENSE_TRACKER_LEGACY_ARCHIVE_ID" in source
    assert "the build will never guess it" in source
    assert '"unknown"' not in source


def test_signed_candidate_workflow_consumes_the_tagged_candidate_directory():
    workflow = (ROOT / ".github" / "workflows" / "v9-signed-candidate.yml").read_text(
        encoding="utf-8"
    )

    assert workflow.count("dist/candidates/v9.0.0/") == 2
    assert '"dist\\candidates\\v9.0.0\\$env:RELEASE_SHA"' in workflow
    assert "-CandidateOnly" in workflow
    assert "dist/releases/9.0.0/" not in workflow
    assert "dist/releases/v9.0.0/" not in workflow
    assert '"dist\\releases\\9.0.0\\$env:RELEASE_SHA"' not in workflow


def test_schema2_build_metadata_names_source_epoch_truthfully(tmp_path):
    metadata = tmp_path / "build-metadata.json"
    metadata.write_text(
        json.dumps(
            {
                "schema": 2,
                "commit": "a" * 40,
                "source_tree": "b" * 40,
                "source_date_epoch_utc": "2026-08-28T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    loaded = load_build_metadata(metadata)
    assert loaded is not None
    assert loaded.source_date_epoch_utc == "2026-08-28T00:00:00Z"


def test_release_manifest_times_require_real_utc_ordering():
    started = parse_utc("2026-08-28T00:00:00.0000000Z", field="started")
    finished = parse_utc("2026-08-28T00:00:01.0000000Z", field="finished")
    assert started.tzinfo == timezone.utc
    assert finished > started
    with pytest.raises(ValueError, match="ending in Z"):
        parse_utc("2026-08-28T00:00:00+08:00", field="started")


def test_desktop_smoke_requires_authenticated_webview_workspace_evidence():
    builder = (ROOT / "scripts" / "Build-AndShip.ps1").read_text(encoding="utf-8")
    finalizer = (ROOT / "scripts" / "Finalize-SignedCandidate.ps1").read_text(
        encoding="utf-8"
    )
    launcher = (ROOT / "launcher.py").read_text(encoding="utf-8")
    smoke_probe = (ROOT / "v9" / "desktop_smoke.py").read_text(encoding="utf-8")
    transport_function = builder[
        builder.index("function Get-SmokeTransportStatus") : builder.index(
            "function Invoke-DesktopSmokeTest"
        )
    ]
    finalizer_transport_function = finalizer[
        finalizer.index("function Get-SmokeTransportStatus") : finalizer.index(
            "function Invoke-DesktopSmokeTest"
        )
    ]
    smoke_function = builder[
        builder.index("function Invoke-DesktopSmokeTest") : builder.index(
            "function Invoke-InstallerLifecycleSmokeTest"
        )
    ]
    finalizer_smoke_function = finalizer[
        finalizer.index("function Invoke-DesktopSmokeTest") : finalizer.index(
            "function Invoke-InstallerLifecycleSmokeTest"
        )
    ]
    installer_smoke_function = builder[
        builder.index("function Invoke-InstallerLifecycleSmokeTest") : builder.index(
            "function Invoke-LegacyMigrationSmokeTest"
        )
    ]
    finalizer_installer_smoke_function = finalizer[
        finalizer.index("function Invoke-InstallerLifecycleSmokeTest") : finalizer.index(
            "function Invoke-LegacyMigrationSmokeTest"
        )
    ]
    assert "DEFENSE_TRACKER_SMOKE_EVIDENCE" in builder
    assert "workspace_ready" in builder
    assert "build_commit -eq $ExpectedCommit" in builder
    assert "StatusCode -in @(200, 302)" not in builder
    assert "Start-Process -FilePath $ExePath -PassThru" in smoke_function
    assert "-WindowStyle Hidden" not in smoke_function
    assert "Start-Process -FilePath $ExePath -PassThru" in finalizer_smoke_function
    assert "-WindowStyle Hidden" not in finalizer_smoke_function
    assert installer_smoke_function.count("-WindowStyle Hidden") == 2
    assert finalizer_installer_smoke_function.count("-WindowStyle Hidden") == 2
    assert "/VERYSILENT" in installer_smoke_function
    assert "/VERYSILENT" in finalizer_installer_smoke_function
    assert "document.querySelector('main.v9-workspace')" in smoke_probe
    assert "payload.build_commit" in smoke_probe
    assert "window.evaluate_js" not in launcher + smoke_probe
    assert "window.run_js" in smoke_probe
    assert "window.expose" not in smoke_probe
    assert "window.pywebview" not in smoke_probe
    assert "json.loads" in smoke_probe
    assert "evidence_path" not in smoke_probe
    assert "evidence_sink=_store_desktop_smoke_evidence" in launcher
    assert '"authenticated-loopback-v1"' in launcher
    assert '"X-Defense-Tracker-Smoke"' in launcher
    assert "hmac.compare_digest" in launcher
    assert "DEFENSE_TRACKER_SMOKE_TOKEN" in builder
    assert "DEFENSE_TRACKER_SMOKE_TOKEN" in finalizer
    assert "Invoke-RestMethod" in smoke_function
    assert "Invoke-RestMethod" in finalizer_smoke_function
    assert "$response.process_id -eq $process.Id" in smoke_function
    assert "$response.process_id -eq $process.Id" in finalizer_smoke_function
    assert "Get-NetTCPConnection -State Listen -OwningProcess $process.Id" in smoke_function
    assert "Get-NetTCPConnection -State Listen -OwningProcess $process.Id" in finalizer_smoke_function
    assert "foreach ($port in 49231..49235)" not in smoke_function
    assert "foreach ($port in 49231..49235)" not in finalizer_smoke_function
    assert "RandomNumberGenerator]::Create()" in smoke_function
    assert "RandomNumberGenerator]::Create()" in finalizer_smoke_function
    assert "[System.IO.FileMode]::CreateNew" in smoke_function
    assert "[System.IO.FileMode]::CreateNew" in finalizer_smoke_function
    assert smoke_function.index("if (-not $workspaceReady)") < smoke_function.index(
        "Get-NetTCPConnection"
    )
    assert finalizer_smoke_function.index(
        "if (-not $workspaceReady)"
    ) < finalizer_smoke_function.index("Get-NetTCPConnection")
    assert "transport=$lastTransportStatus" in smoke_function
    assert "transport=$lastTransportStatus" in finalizer_smoke_function
    assert "$_.Exception.Response" not in smoke_function
    assert "$_.Exception.Response" not in finalizer_smoke_function
    assert "Get-SmokeTransportStatus -ErrorRecord $_" in smoke_function
    assert "Get-SmokeTransportStatus -ErrorRecord $_" in finalizer_smoke_function
    assert "PSObject.Properties" in transport_function
    assert "PSObject.Properties" in finalizer_transport_function
    assert "connection-error" in transport_function
    assert "connection-error" in finalizer_transport_function
    assert "listener_query=$lastListenerQuery" in smoke_function
    assert "listener_query=$lastListenerQuery" in finalizer_smoke_function
    assert "Get-NetTCPConnection" in smoke_function and "-ErrorAction Stop" in smoke_function
    assert "Get-NetTCPConnection" in finalizer_smoke_function
    assert "-ErrorAction Stop" in finalizer_smoke_function
    assert "Invoke-InstallerLifecycleSmokeTest" in builder
    assert "Silent uninstall left the installed application executable behind" in builder
    assert "Invoke-DesktopSmokeTest $portableExe" in builder
    assert "Invoke-LegacyMigrationSmokeTest" in builder
    assert "Legacy migration overwrote existing runtime configuration" in builder


@pytest.mark.parametrize(
    "relative_path",
    (
        "scripts/Build-AndShip.ps1",
        "scripts/Finalize-SignedCandidate.ps1",
    ),
)
def test_smoke_transport_status_is_strictmode_safe(tmp_path, relative_path):
    source = (ROOT / relative_path).read_text(encoding="utf-8-sig")
    function_start = source.index("function Get-SmokeTransportStatus")
    function_end = source.index("function Invoke-DesktopSmokeTest", function_start)
    function_source = source[function_start:function_end]
    probe = tmp_path / f"transport-{Path(relative_path).stem}.ps1"
    probe.write_text(
        "$ErrorActionPreference = 'Stop'\n"
        "Set-StrictMode -Version Latest\n"
        + function_source
        + "\n"
        + "$missing = [pscustomobject]@{ Exception = "
        "[System.InvalidOperationException]::new('missing') }\n"
        + "$nullResponse = [pscustomobject]@{ Exception = "
        "[System.Net.WebException]::new('null') }\n"
        + "$httpResponse = [pscustomobject]@{ Exception = [pscustomobject]@{ "
        "Response = [pscustomobject]@{ StatusCode = 503 } } }\n"
        + "@($missing, $nullResponse, $httpResponse) | ForEach-Object { "
        "Get-SmokeTransportStatus -ErrorRecord $_ }\n",
        encoding="utf-8-sig",
    )
    result = subprocess.run(
        [_powershell(), "-NoProfile", "-File", str(probe)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines() == [
        "connection-error",
        "connection-error",
        "http-503",
    ]
