import json
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]


def test_webview2_runtime_lock_is_immutable_microsoft_x64_identity():
    lock = json.loads(
        (ROOT / "release" / "webview2-runtime-lock.json").read_text(encoding="utf-8")
    )

    assert set(lock) == {
        "architecture",
        "bytes",
        "distribution",
        "installer_file_version",
        "original_filename",
        "publisher_subject",
        "retrieved_utc",
        "schema",
        "sha256",
        "source_url",
    }
    source = urlsplit(lock["source_url"])
    assert lock["schema"] == 1
    assert lock["distribution"] == "evergreen-standalone"
    assert lock["architecture"] == "x64"
    assert source.scheme == "https"
    assert source.hostname == "msedge.sf.dl.delivery.mp.microsoft.com"
    assert "go.microsoft.com" not in lock["source_url"]
    assert source.path.endswith("/MicrosoftEdgeWebView2RuntimeInstallerX64.exe")
    assert len(lock["sha256"]) == 64
    assert int(lock["sha256"], 16) >= 0
    assert lock["bytes"] == 258438352
    assert lock["publisher_subject"].startswith("CN=Microsoft Corporation,")


def test_unsigned_candidate_installs_verified_runtime_before_building():
    workflow = (ROOT / ".github/workflows/v9-development-candidate.yml").read_text(
        encoding="utf-8"
    )
    installer = (
        ROOT / "scripts" / "Install-VerifiedWebView2Runtime.ps1"
    ).read_text(encoding="utf-8")

    runtime_step = workflow.index("Install hash-pinned Microsoft WebView2 Runtime")
    prepare_step = workflow.index("Prepare one-use hash-locked unsigned-development")
    build_step = workflow.index("Build, privacy-scan, PE-check")
    assert runtime_step < prepare_step < build_step
    assert ".\\scripts\\Install-VerifiedWebView2Runtime.ps1" in workflow
    for requirement in (
        "Get-FileHash",
        "Get-AuthenticodeSignature",
        "SignatureStatus]::Valid",
        "publisher_subject",
        "installer_file_version",
        "original_filename",
        "WebView2 Runtime was not registered",
        "[System.Version]'86.0.622.0'",
        "'^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'",
        "[System.Version]::TryParse",
        "$parsedVersion -ge $minimumRuntimeVersion",
    ):
        assert requirement in installer
    assert "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\EdgeUpdate" not in installer
    assert "Invoke-Expression" not in installer
    assert "DownloadString" not in installer
