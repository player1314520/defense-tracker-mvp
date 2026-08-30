import shutil
import subprocess
from pathlib import Path

import pytest

from scripts import prepare_mvp_portal_context


ROOT = Path(__file__).resolve().parents[1]


def _powershell() -> str:
    executable = shutil.which("pwsh") or shutil.which("powershell")
    if executable is None:
        pytest.skip("PowerShell is unavailable")
    return executable


@pytest.mark.parametrize(
    ("relative_path", "next_function"),
    (
        ("scripts/Build-AndShip.ps1", "function Assert-WindowsPeFile"),
        ("scripts/Finalize-SignedCandidate.ps1", "function Invoke-DesktopSmokeTest"),
    ),
)
def test_artifact_scanners_ignore_embedded_substrings_but_reject_real_tokens(
    tmp_path: Path,
    relative_path: str,
    next_function: str,
):
    source = (ROOT / relative_path).read_text(encoding="utf-8-sig")
    function_start = source.index("function Get-ArtifactSafetyFindings")
    function_end = source.index(next_function, function_start)
    function_source = source[function_start:function_end]

    artifact_root = tmp_path / "artifact"
    artifact_root.mkdir()
    tokens = {
        "aws": b"A" + b"KIA" + (b"A" * 16),
        "github": b"g" + b"hp_" + (b"A" * 40),
        "openai": b"s" + b"k-" + (b"A" * 32),
    }
    for name, token in tokens.items():
        (artifact_root / f"embedded-{name}.dat").write_bytes(
            b"babel-v" + token + b"-locale"
        )
        (artifact_root / f"hyphenated-{name}.dat").write_bytes(
            b"label-" + token + b"-locale"
        )
        (artifact_root / f"standalone-{name}.dat").write_bytes(
            b"\x00" + token + b"\x00"
        )
    (artifact_root / "invalid-aws-suffix.dat").write_bytes(
        b"\x00" + tokens["aws"] + b"X\x00"
    )
    split_padding = b"\x00" * 65_530
    (artifact_root / "cross-chunk-real.dat").write_bytes(
        split_padding + b"\x00" + tokens["openai"] + b"\x00"
    )
    (artifact_root / "cross-chunk-embedded.dat").write_bytes(
        split_padding + b"v" + tokens["openai"] + b"\x00"
    )

    quoted_root = str(artifact_root).replace("'", "''")
    probe = tmp_path / "probe.ps1"
    probe.write_text(
        "$ErrorActionPreference = 'Stop'\n"
        + function_source
        + "\n"
        + f"Get-ArtifactSafetyFindings -Root '{quoted_root}'\n",
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
    assert sorted(result.stdout.splitlines()) == [
        "secret-content:cross-chunk-real.dat",
        "secret-content:standalone-aws.dat",
        "secret-content:standalone-github.dat",
        "secret-content:standalone-openai.dat",
    ]


@pytest.mark.parametrize(
    "token",
    (
        b"s" + b"k-" + (b"A" * 24),
        b"s" + b"k-proj-" + (b"A" * 24),
        b"g" + b"hp_" + (b"A" * 32),
        b"s" + b"b_secret_" + (b"A" * 24),
    ),
)
def test_portal_context_scanner_uses_the_same_token_boundary(token: bytes):
    for prefix in (b"v", b"_", b"label-"):
        assert not any(
            pattern.search(prefix + token + b"\x00")
            for pattern in prepare_mvp_portal_context.SECRET_PATTERNS
        )
    for prefix in (b"", b"\x00", b'"', b"Bearer ", b"KEY="):
        assert any(
            pattern.search(prefix + token + b"\x00")
            for pattern in prepare_mvp_portal_context.SECRET_PATTERNS
        )


def test_portal_context_scanner_preserves_the_minimum_token_length():
    too_short = b"s" + b"k-" + (b"A" * 15)

    assert not any(
        pattern.search(b"\x00" + too_short + b"\x00")
        for pattern in prepare_mvp_portal_context.SECRET_PATTERNS
    )
