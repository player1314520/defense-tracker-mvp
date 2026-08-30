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


def _run_artifact_scanner(
    tmp_path: Path,
    relative_path: str,
    next_function: str,
    artifact_root: Path,
) -> list[str]:
    source = (ROOT / relative_path).read_text(encoding="utf-8-sig")
    function_start = source.index("function Get-ArtifactSafetyFindings")
    function_end = source.index(next_function, function_start)
    function_source = source[function_start:function_end]

    quoted_root = str(artifact_root).replace("'", "''")
    probe = tmp_path / f"probe-{Path(relative_path).stem}.ps1"
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
    return sorted(result.stdout.splitlines())


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
    artifact_root = tmp_path / "artifact"
    artifact_root.mkdir()
    tokens = {
        "aws": b"A" + b"KIA" + (b"A" * 16),
        "github": b"g" + b"hp_" + (b"A" * 40),
        "openai": b"s" + b"k-" + (b"A" * 32),
        "supabase": b"s" + b"b_secret_" + (b"A" * 32),
    }
    for name, token in tokens.items():
        (artifact_root / f"embedded-{name}.dat").write_bytes(
            b"babel-v" + token + b"-locale"
        )
        (artifact_root / f"hyphenated-{name}.dat").write_bytes(
            b"label-" + token + b"-locale"
        )
        (artifact_root / f"underscored-{name}.dat").write_bytes(
            b"label_" + token + b"_locale"
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

    assert _run_artifact_scanner(
        tmp_path, relative_path, next_function, artifact_root
    ) == [
        "secret-content:cross-chunk-real.dat",
        "secret-content:hyphenated-aws.dat",
        "secret-content:hyphenated-github.dat",
        "secret-content:hyphenated-openai.dat",
        "secret-content:hyphenated-supabase.dat",
        "secret-content:standalone-aws.dat",
        "secret-content:standalone-github.dat",
        "secret-content:standalone-openai.dat",
        "secret-content:standalone-supabase.dat",
        "secret-content:underscored-aws.dat",
        "secret-content:underscored-github.dat",
        "secret-content:underscored-openai.dat",
        "secret-content:underscored-supabase.dat",
    ]


@pytest.mark.parametrize(
    ("relative_path", "next_function"),
    (
        ("scripts/Build-AndShip.ps1", "function Assert-WindowsPeFile"),
        ("scripts/Finalize-SignedCandidate.ps1", "function Invoke-DesktopSmokeTest"),
    ),
)
def test_text_artifact_scanners_share_provider_families_and_thresholds(
    tmp_path: Path,
    relative_path: str,
    next_function: str,
):
    artifact_root = tmp_path / "text-artifact"
    artifact_root.mkdir()
    tokens = {
        "aws": b"A" + b"KIA" + (b"A" * 16),
        "github": b"g" + b"hp_" + (b"A" * 20),
        "openai": b"s" + b"k-" + (b"A" * 16),
        "supabase": b"s" + b"b_secret_" + (b"A" * 16),
    }
    for name, token in tokens.items():
        (artifact_root / f"standalone-{name}.txt").write_bytes(
            b"KEY=" + token + b"\n"
        )
    (artifact_root / "embedded-openai.txt").write_bytes(
        b"babel-v" + tokens["openai"] + b"\n"
    )
    (artifact_root / "short-openai.txt").write_bytes(
        b"KEY=" + b"s" + b"k-" + (b"A" * 15) + b"\n"
    )

    assert _run_artifact_scanner(
        tmp_path, relative_path, next_function, artifact_root
    ) == [
        "secret-content:standalone-aws.txt",
        "secret-content:standalone-github.txt",
        "secret-content:standalone-openai.txt",
        "secret-content:standalone-supabase.txt",
    ]


@pytest.mark.parametrize(
    "token",
    (
        b"s" + b"k-" + (b"A" * 24),
        b"s" + b"k-proj-" + (b"A" * 24),
        b"g" + b"hp_" + (b"A" * 32),
        b"A" + b"KIA" + (b"A" * 16),
        b"s" + b"b_secret_" + (b"A" * 24),
    ),
)
def test_portal_context_scanner_uses_provider_specific_boundaries(token: bytes):
    assert not prepare_mvp_portal_context._contains_high_confidence_secret(
        b"v" + token + b"\x00"
    )
    for prefix in (b"", b"\x00", b'"', b"Bearer ", b"KEY=", b"_", b"label-"):
        assert prepare_mvp_portal_context._contains_high_confidence_secret(
            prefix + token + b"\x00"
        )


@pytest.mark.parametrize(
    "too_short_or_long",
    (
        b"s" + b"k-" + (b"A" * 15),
        b"g" + b"hp_" + (b"A" * 19),
        b"A" + b"KIA" + (b"A" * 15),
        b"A" + b"KIA" + (b"A" * 17),
        b"s" + b"b_secret_" + (b"A" * 15),
    ),
)
def test_portal_context_scanner_preserves_provider_lengths(
    too_short_or_long: bytes,
):
    assert not prepare_mvp_portal_context._contains_high_confidence_secret(
        b"\x00" + too_short_or_long + b"\x00"
    )
