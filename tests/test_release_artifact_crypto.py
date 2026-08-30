import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
INITIALIZE = ROOT / "scripts" / "Initialize-ReleaseArtifactCrypto.ps1"
PROTECT = ROOT / "scripts" / "Protect-ReleaseArtifact.ps1"
UNPROTECT = ROOT / "scripts" / "Unprotect-ReleaseArtifact.ps1"
MODULE = ROOT / "scripts" / "ReleaseArtifactCrypto.psm1"
TRACKED_RECIPIENT = ROOT / "release" / "candidate-transport-recipient.txt"
RECIPIENT = "age1g0mg6lvh0afw0placc32zcfau3ry28c0duk3vuc5uqugy7w869fsa0hs44"


def _powershell() -> str:
    candidates = (
        ("powershell", "pwsh") if os.name == "nt" else ("pwsh", "powershell")
    )
    for candidate in candidates:
        executable = shutil.which(candidate)
        if executable is not None:
            return executable
    pytest.skip("PowerShell is unavailable")


def _run(script: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        [
            _powershell(),
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            *map(str, arguments),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if check:
        assert result.returncode == 0, result.stdout + result.stderr
    return result


def _fake_age(tmp_path: Path) -> tuple[Path, str]:
    if os.name != "nt":
        executable = tmp_path / "fake-age"
        executable.write_text(
            "#!/usr/bin/env sh\n"
            "set -eu\n"
            "if [ \"${1-}\" = \"--version\" ]; then\n"
            "  printf '%s\\n' 'v1.3.2'\n"
            "  exit 0\n"
            "fi\n"
            "mode=${1-}\n"
            "if [ \"$mode\" != \"--encrypt\" ] && [ \"$mode\" != \"--decrypt\" ]; then\n"
            "  exit 20\n"
            "fi\n"
            "shift\n"
            "keyfile=\n"
            "output=\n"
            "input=\n"
            "while [ \"$#\" -gt 0 ]; do\n"
            "  case \"$1\" in\n"
            "    --recipients-file|--identity)\n"
            "      [ \"$#\" -ge 2 ] || exit 20\n"
            "      keyfile=$2\n"
            "      shift 2\n"
            "      ;;\n"
            "    --output)\n"
            "      [ \"$#\" -ge 2 ] || exit 20\n"
            "      output=$2\n"
            "      shift 2\n"
            "      ;;\n"
            "    --*) exit 20 ;;\n"
            "    *)\n"
            "      [ -z \"$input\" ] || exit 20\n"
            "      input=$1\n"
            "      shift\n"
            "      ;;\n"
            "  esac\n"
            "done\n"
            "[ -n \"$keyfile\" ] && [ -f \"$keyfile\" ] || exit 21\n"
            "[ -n \"$input\" ] && [ -f \"$input\" ] || exit 22\n"
            "[ -n \"$output\" ] || exit 23\n"
            "cp -- \"$input\" \"$output\" || exit 23\n",
            encoding="ascii",
            newline="",
        )
        executable.chmod(0o700)
        digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        return executable, digest

    executable = tmp_path / "fake-age.cmd"
    executable.write_text(
        "@echo off\r\n"
        "setlocal EnableExtensions\r\n"
        "if \"%~1\"==\"--version\" (echo v1.3.2& exit /b 0)\r\n"
        "set \"mode=%~1\"\r\n"
        "shift\r\n"
        ":parse\r\n"
        "if \"%~1\"==\"\" goto done\r\n"
        "if \"%~1\"==\"--recipients-file\" (\r\n"
        "  set \"keyfile=%~2\"\r\n"
        "  shift\r\n"
        "  shift\r\n"
        "  goto parse\r\n"
        ")\r\n"
        "if \"%~1\"==\"--identity\" (\r\n"
        "  set \"keyfile=%~2\"\r\n"
        "  shift\r\n"
        "  shift\r\n"
        "  goto parse\r\n"
        ")\r\n"
        "if \"%~1\"==\"--output\" (\r\n"
        "  set \"output=%~2\"\r\n"
        "  shift\r\n"
        "  shift\r\n"
        "  goto parse\r\n"
        ")\r\n"
        "set \"input=%~1\"\r\n"
        "shift\r\n"
        "goto parse\r\n"
        ":done\r\n"
        "if not exist \"%keyfile%\" exit /b 21\r\n"
        "if not exist \"%input%\" exit /b 22\r\n"
        "copy /b /y \"%input%\" \"%output%\" >nul\r\n"
        "if errorlevel 1 exit /b 23\r\n"
        "exit /b 0\r\n",
        encoding="ascii",
        newline="",
    )
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    return executable, digest


def _secret_identity() -> str:
    # Deliberately assembled at runtime so no private-key-shaped literal is tracked.
    return "AGE" + "-SECRET-KEY-1" + ("A" * 58)


def _make_inputs(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    plaintext = tmp_path / "plaintext"
    (plaintext / "nested").mkdir(parents=True)
    (plaintext / "candidate.exe").write_bytes(b"MZ\x00candidate")
    (plaintext / "nested" / "review.json").write_text(
        '{"approved":false}', encoding="utf-8"
    )
    recipient = tmp_path / "recipient.txt"
    recipient.write_text(RECIPIENT + "\n", encoding="utf-8", newline="")
    age, age_sha = _fake_age(tmp_path)
    return plaintext, recipient, age, age_sha


def _protect(tmp_path: Path) -> tuple[Path, Path, str]:
    plaintext, recipient, age, age_sha = _make_inputs(tmp_path)
    envelope = tmp_path / "envelope"
    _run(
        PROTECT,
        "-AgeExecutable",
        age,
        "-ExpectedAgeExecutableSha256",
        age_sha,
        "-PlaintextRoot",
        plaintext,
        "-RecipientFile",
        recipient,
        "-OutputDirectory",
        envelope,
        "-ArtifactName",
        "DefenseTracker-v9-preparation",
        "-Repository",
        "player1314520/defense-tracker-mvp",
        "-ReleaseCommit",
        "a" * 40,
        "-RunId",
        "123456789",
        "-RunAttempt",
        "1",
        "-TemporaryDirectory",
        tmp_path,
    )
    return envelope, age, age_sha


def _identity_file(tmp_path: Path) -> Path:
    identity = tmp_path / "identity.txt"
    identity.write_text(_secret_identity() + "\n", encoding="utf-8", newline="")
    return identity


def _unprotect(
    tmp_path: Path,
    envelope: Path,
    age: Path,
    age_sha: str,
    *,
    check: bool = True,
) -> tuple[subprocess.CompletedProcess, Path, Path]:
    identity = _identity_file(tmp_path)
    output = tmp_path / "decrypted"
    result = _run(
        UNPROTECT,
        "-AgeExecutable",
        age,
        "-ExpectedAgeExecutableSha256",
        age_sha,
        "-EnvelopeDirectory",
        envelope,
        "-IdentityFile",
        identity,
        "-OutputDirectory",
        output,
        "-ExpectedRepository",
        "player1314520/defense-tracker-mvp",
        "-ExpectedReleaseCommit",
        "a" * 40,
        "-ExpectedRunId",
        "123456789",
        "-ExpectedRunAttempt",
        "1",
        "-RemoveIdentityFile",
        "-TemporaryDirectory",
        tmp_path,
        check=check,
    )
    return result, output, identity


def test_initializer_pins_official_age_archive_and_exact_version_output():
    source = INITIALIZE.read_text(encoding="utf-8")

    assert "$ageVersion = '1.3.2'" in source
    assert (
        "$ageArchiveSha256 = "
        "'f48d8f8f9ebe903ab5027ed067652f2cc1db94bc206976430133b905dcd8e8c7'"
    ) in source
    assert (
        "https://github.com/FiloSottile/age/releases/download/v1.3.2/"
        "age-v1.3.2-windows-amd64.zip"
    ) in source
    assert '$versionOutput -cne "v$ageVersion"' in source
    assert "Get-Sha256 -Path $archivePath" in source
    assert "age-keygen" not in source.lower()


def test_initializer_fails_closed_outside_github_hosted_windows(tmp_path: Path):
    github_env = tmp_path / "github-env.txt"
    github_env.write_text("", encoding="utf-8")
    environment = os.environ.copy()
    environment.update(
        {
            "GITHUB_ACTIONS": "false",
            "RUNNER_ENVIRONMENT": "self-hosted",
            "RUNNER_OS": "Windows",
            "GITHUB_ENV": str(github_env),
            "RUNNER_TEMP": str(tmp_path),
        }
    )
    result = subprocess.run(
        [
            _powershell(),
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(INITIALIZE),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=environment,
        check=False,
    )

    assert result.returncode != 0
    assert "restricted to an ephemeral GitHub-hosted Windows runner" in (
        result.stdout + result.stderr
    )
    assert not list(tmp_path.glob("defense-tracker-age-v*"))


def test_tracked_public_recipient_and_environment_secret_contract_are_exact():
    recipient_bytes = TRACKED_RECIPIENT.read_bytes()
    recipient_text = recipient_bytes.decode("utf-8")
    protect_source = PROTECT.read_text(encoding="utf-8")
    unprotect_source = UNPROTECT.read_text(encoding="utf-8")

    assert not recipient_bytes.startswith(b"\xef\xbb\xbf")
    assert "\r" not in recipient_text
    assert re.fullmatch(r"age1[0-9a-z]{58}\n?", recipient_text)
    assert "..\\release\\candidate-transport-recipient.txt" in protect_source
    assert "RELEASE_ARTIFACT_AGE_IDENTITY" in unprotect_source
    assert "$env:RELEASE_ARTIFACT_AGE_IDENTITY" not in unprotect_source


def test_all_transport_scripts_parse_with_windows_powershell():
    quoted = ",".join(f"'{str(path).replace(chr(39), chr(39) * 2)}'" for path in (
        MODULE,
        INITIALIZE,
        PROTECT,
        UNPROTECT,
    ))
    command = (
        f"$files=@({quoted});"
        "$failed=$false;"
        "foreach($file in $files){"
        "$tokens=$null;$errors=$null;"
        "[System.Management.Automation.Language.Parser]::ParseFile("
        "$file,[ref]$tokens,[ref]$errors)|Out-Null;"
        "if($errors.Count){$failed=$true;$errors|ForEach-Object{$_.Message}}};"
        "if($failed){exit 1}"
    )
    result = subprocess.run(
        [_powershell(), "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_round_trip_outputs_only_strict_public_envelope_and_removes_identity(tmp_path: Path):
    envelope, age, age_sha = _protect(tmp_path)

    assert sorted(path.name for path in envelope.iterdir()) == [
        "DefenseTracker-v9-preparation.age",
        "candidate-transport-receipt.json",
        "candidate-transport-request.json",
    ]
    request_path = envelope / "candidate-transport-request.json"
    receipt_path = envelope / "candidate-transport-receipt.json"
    for path in (request_path, receipt_path):
        raw = path.read_bytes()
        assert not raw.startswith(b"\xef\xbb\xbf")
        assert not raw.endswith(b"\n")
        parsed = json.loads(raw)
        assert raw == json.dumps(
            parsed, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
    assert list(json.loads(request_path.read_text(encoding="utf-8"))) == [
        "artifact_name",
        "recipient_file_sha256",
        "release_commit",
        "repository",
        "run_attempt",
        "run_id",
        "schema",
    ]
    assert list(json.loads(receipt_path.read_text(encoding="utf-8"))) == [
        "ciphertext_file",
        "ciphertext_sha256",
        "ciphertext_size",
        "plaintext_archive_sha256",
        "plaintext_archive_size",
        "request_file",
        "request_sha256",
        "schema",
    ]

    result, output, identity = _unprotect(tmp_path, envelope, age, age_sha)

    assert result.returncode == 0
    assert not identity.exists()
    assert (output / "candidate.exe").read_bytes() == b"MZ\x00candidate"
    assert json.loads((output / "nested" / "review.json").read_text()) == {
        "approved": False
    }


def test_unprotect_rejects_any_extra_envelope_file_and_cleans_identity(tmp_path: Path):
    envelope, age, age_sha = _protect(tmp_path)
    (envelope / "unexpected.txt").write_text("not allowed", encoding="utf-8")

    result, output, identity = _unprotect(
        tmp_path, envelope, age, age_sha, check=False
    )

    assert result.returncode != 0
    assert "must contain exactly one .age file" in (result.stdout + result.stderr)
    assert not output.exists()
    assert not identity.exists()


def test_unprotect_rejects_wrong_ciphertext_hash_before_decryption(tmp_path: Path):
    envelope, age, age_sha = _protect(tmp_path)
    ciphertext = envelope / "DefenseTracker-v9-preparation.age"
    ciphertext.write_bytes(ciphertext.read_bytes() + b"tamper")

    result, output, identity = _unprotect(
        tmp_path, envelope, age, age_sha, check=False
    )

    assert result.returncode != 0
    assert "ciphertext hash or size mismatch" in (result.stdout + result.stderr)
    assert not output.exists()
    assert not identity.exists()


def test_unprotect_rejects_wrong_plaintext_hash_after_decryption(tmp_path: Path):
    envelope, age, age_sha = _protect(tmp_path)
    receipt_path = envelope / "candidate-transport-receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["plaintext_archive_sha256"] = "0" * 64
    receipt_path.write_text(
        json.dumps(receipt, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
        newline="",
    )

    result, output, identity = _unprotect(
        tmp_path, envelope, age, age_sha, check=False
    )

    assert result.returncode != 0
    assert "plaintext archive hash or size mismatch" in (result.stdout + result.stderr)
    assert not output.exists()
    assert not identity.exists()


def test_protect_rejects_recipient_newline_injection_without_output(tmp_path: Path):
    plaintext, recipient, age, age_sha = _make_inputs(tmp_path)
    recipient.write_text(RECIPIENT + "\n" + RECIPIENT, encoding="utf-8", newline="")
    envelope = tmp_path / "envelope"

    result = _run(
        PROTECT,
        "-AgeExecutable",
        age,
        "-ExpectedAgeExecutableSha256",
        age_sha,
        "-PlaintextRoot",
        plaintext,
        "-RecipientFile",
        recipient,
        "-OutputDirectory",
        envelope,
        "-ArtifactName",
        "DefenseTracker-v9-preparation",
        "-Repository",
        "player1314520/defense-tracker-mvp",
        "-ReleaseCommit",
        "a" * 40,
        "-RunId",
        "123",
        "-RunAttempt",
        "1",
        "-TemporaryDirectory",
        tmp_path,
        check=False,
    )

    assert result.returncode != 0
    assert "no injected line" in (result.stdout + result.stderr)
    assert not envelope.exists()


def test_protect_rejects_reparse_point_in_plaintext_tree(tmp_path: Path):
    plaintext, recipient, age, age_sha = _make_inputs(tmp_path)
    target = tmp_path / "outside"
    target.mkdir()
    (target / "outside.txt").write_text("outside", encoding="utf-8")
    link = plaintext / "linked-directory"
    junction_command = (
        "$ErrorActionPreference='Stop';"
        f"New-Item -ItemType Junction -Path '{str(link).replace(chr(39), chr(39) * 2)}' "
        f"-Target '{str(target).replace(chr(39), chr(39) * 2)}' | Out-Null"
    )
    junction = subprocess.run(
        [_powershell(), "-NoProfile", "-Command", junction_command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if junction.returncode != 0:
        pytest.skip("directory junction creation unavailable")
    envelope = tmp_path / "envelope"

    result = _run(
        PROTECT,
        "-AgeExecutable",
        age,
        "-ExpectedAgeExecutableSha256",
        age_sha,
        "-PlaintextRoot",
        plaintext,
        "-RecipientFile",
        recipient,
        "-OutputDirectory",
        envelope,
        "-ArtifactName",
        "DefenseTracker-v9-preparation",
        "-Repository",
        "player1314520/defense-tracker-mvp",
        "-ReleaseCommit",
        "a" * 40,
        "-RunId",
        "123",
        "-RunAttempt",
        "1",
        "-TemporaryDirectory",
        tmp_path,
        check=False,
    )

    assert result.returncode != 0
    assert "reparse point" in (result.stdout + result.stderr)
    assert not envelope.exists()
    link.rmdir()


def test_transport_source_never_generates_or_embeds_a_private_identity():
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (INITIALIZE, PROTECT, UNPROTECT, MODULE)
    )

    assert "age-keygen" not in source.lower()
    assert "$env:RELEASE_ARTIFACT_AGE_IDENTITY" not in source
    assert "FromBase64String" not in source
    assert re.search(r"AGE-SECRET-KEY-1[023456789ACDEFGHJKLMNPQRSTUVWXYZ]{58}", source) is None
    assert "RemoveIdentityFile" in source
    assert "finally" in source
