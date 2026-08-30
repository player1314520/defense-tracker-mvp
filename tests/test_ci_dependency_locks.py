from __future__ import annotations

import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
COMPILER = ROOT / "scripts" / "Compile-DependencyLocks.ps1"

CI_LOCKS = {
    "ubuntu-latest": "requirements.ci-linux.lock",
    "windows-latest": "requirements.ci-windows.lock",
}
DEPLOYMENT_INPUT = "requirements.ci-deployment.in"
DEPLOYMENT_LOCK = "requirements.ci-deployment.lock"
ISOLATION_SPEC = "supabase/tests/v9_sync_byte_quota_isolation.spec"


def _direct_pins(path: Path) -> set[str]:
    pins: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        assert re.fullmatch(r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.+-]+", line), line
        pins.add(line.split("==", 1)[0].lower())
    return pins


def _locked_names(path: Path) -> set[str]:
    source = path.read_text(encoding="utf-8")
    names = {
        name.lower()
        for name in re.findall(
            r"(?m)^([A-Za-z0-9_.-]+)==[^\s\\]+(?:\s*\\)?$", source
        )
    }
    assert names
    assert source.count("--hash=sha256:") >= len(names)
    return names


def test_ci_inputs_are_exact_platform_pins_and_locks_cover_them():
    pairs = (
        ("requirements.ci-linux.in", CI_LOCKS["ubuntu-latest"]),
        ("requirements.ci-windows.in", CI_LOCKS["windows-latest"]),
        (DEPLOYMENT_INPUT, DEPLOYMENT_LOCK),
    )
    for input_name, lock_name in pairs:
        direct = _direct_pins(ROOT / input_name)
        assert direct
        assert direct <= _locked_names(ROOT / lock_name)

    linux = _direct_pins(ROOT / "requirements.ci-linux.in")
    windows = _direct_pins(ROOT / "requirements.ci-windows.in")
    deployment = _direct_pins(ROOT / DEPLOYMENT_INPUT)
    shared_test_runtime = {
        "apscheduler",
        "beautifulsoup4",
        "cryptography",
        "feedparser",
        "flask",
        "lxml",
        "openpyxl",
        "pdfplumber",
        "pytest",
        "python-docx",
        "pyyaml",
        "reportlab",
        "requests",
        "trafilatura",
    }
    assert linux == shared_test_runtime
    assert windows == shared_test_runtime | {"pywebview"}
    assert deployment == {"pytest", "pyyaml"}


def test_ci_installs_only_complete_hash_locks_and_caches_by_lock():
    source = WORKFLOW.read_text(encoding="utf-8")
    workflow = yaml.safe_load(source)

    matrix = workflow["jobs"]["python-tests"]["strategy"]["matrix"]["include"]
    assert {item["os"]: item["python-lock"] for item in matrix} == CI_LOCKS
    assert {item["os"]: item["source-exceptions"] for item in matrix} == {
        "ubuntu-latest": "sgmllib3k",
        "windows-latest": "sgmllib3k,proxy-tools",
    }
    python_job = workflow["jobs"]["python-tests"]
    python_setup = next(
        step for step in python_job["steps"] if step.get("uses", "").startswith("actions/setup-python@")
    )
    assert python_setup["with"]["cache-dependency-path"].splitlines() == [
        "requirements.bootstrap.lock",
        "${{ matrix.python-lock }}",
    ]
    python_install = next(
        step for step in python_job["steps"] if step.get("name") == "Install hash-locked test dependencies"
    )["run"]
    assert "--require-hashes" in python_install
    assert "--only-binary=:all:" in python_install
    assert "--no-binary=${{ matrix.source-exceptions }}" in python_install
    assert "--no-build-isolation" in python_install
    assert "-r ${{ matrix.python-lock }}" in python_install
    assert any(
        step.get("run") == "python -m pip check" for step in python_job["steps"]
    )

    deployment_job = workflow["jobs"]["deployment-assets"]
    deployment_setup = next(
        step
        for step in deployment_job["steps"]
        if step.get("uses", "").startswith("actions/setup-python@")
    )
    assert deployment_setup["with"]["cache"] == "pip"
    assert deployment_setup["with"]["cache-dependency-path"] == DEPLOYMENT_LOCK
    deployment_install = next(
        step
        for step in deployment_job["steps"]
        if step.get("name") == "Install hash-locked deployment test dependencies"
    )["run"]
    assert "--require-hashes" in deployment_install
    assert "--only-binary=:all:" in deployment_install
    assert f"-r {DEPLOYMENT_LOCK}" in deployment_install
    assert any(
        step.get("run") == "python -m pip check"
        for step in deployment_job["steps"]
    )

    for forbidden in (
        "requirements.txt",
        "requirements-dev.txt",
        '"PyYAML==',
        "pip install pytest",
    ):
        assert forbidden not in source


def test_lock_compiler_bootstraps_official_uv_with_checksum_to_a_temp_path():
    source = COMPILER.read_text(encoding="utf-8")
    assert 'UvVersion = "0.9.27"' in source
    assert 'ExcludeNewer = "2026-08-28T00:00:00Z"' in source
    assert "github.com/astral-sh/uv/releases/download" in source
    assert '"$releaseBase/$asset.sha256"' in source
    assert "Get-FileHash" in source
    assert "c3bf465d5f2b93c836f369aec9f3fa8350843f24abd5f710bb74e72440b82898" in source
    assert "8636e693ea0e05f5f4294b161f816c4d8df065267fdb0405cfb84c8e326991fa" in source
    assert "GetTempPath" in source
    assert "Remove-Item" in source
    assert "pip install uv" not in source
    for path in (
        "requirements.ci-linux.in",
        "requirements.ci-linux.lock",
        "requirements.ci-windows.in",
        "requirements.ci-windows.lock",
        DEPLOYMENT_INPUT,
        DEPLOYMENT_LOCK,
    ):
        assert path in source


def test_ci_executes_the_tracked_postgres_isolation_spec_with_pinned_source():
    source = WORKFLOW.read_text(encoding="utf-8")
    workflow = yaml.safe_load(source)
    deployment_steps = workflow["jobs"]["deployment-assets"]["steps"]
    isolation = next(
        step
        for step in deployment_steps
        if step.get("name") == "Run atomic organization-byte quota isolation test"
    )
    command = isolation["run"]

    assert workflow["env"]["POSTGRESQL_ISOLATION_VERSION"] == "15.19"
    assert workflow["env"]["POSTGRESQL_ISOLATION_SHA256"] == (
        "e1a64a87a46b825b88c082e4518161a47aab53c45694964f8ba1df28f7859f89"
    )
    assert "ftp.postgresql.org/pub/source" in command
    assert "sha256sum --check --strict" in command
    assert "make -C src/test/isolation isolationtester" in command
    assert "make -C src/test/isolation -j" not in command
    assert ISOLATION_SPEC in command
    assert 'url.hostname == "127.0.0.1"' in command
    assert "expected exactly the two reviewed permutations" in command
    assert "daily organization sync byte limit exceeded" in command
    assert "setup failed:" in command and "teardown failed:" in command

    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert f"!{ISOLATION_SPEC}" in ignore
