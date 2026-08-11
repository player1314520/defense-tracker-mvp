# -*- coding: utf-8 -*-
"""P0 build scripts must remain deterministic and secret-free."""
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_builder_has_no_installer_or_user_data_preservation():
    source = (PROJECT_ROOT / "scripts" / "build_app.py").read_text(encoding="utf-8")

    assert '"pip", "install"' not in source
    assert "KEEP_FILES" not in source
    assert "KEEP_DIRS" not in source
    assert ".access_token" not in source
    assert ".ai_config.json" not in source
    assert "素材库" not in source
    assert "input(" not in source


def test_builder_targets_staging_and_never_replaces_release():
    source = (PROJECT_ROOT / "scripts" / "build_app.py").read_text(encoding="utf-8")

    assert "--distpath" in source
    assert "release-staging" in source
    assert 'os.path.join(BASE, "dist")' not in source


def test_build_gate_requires_isolated_python_and_full_release_checks():
    source = (PROJECT_ROOT / "scripts" / "Build-AndShip.ps1").read_text(
        encoding="utf-8-sig"
    )

    assert ".venv-build" in source
    assert "Get-ArtifactSafetyFindings" in source
    assert "Assert-WindowsPeFile" in source
    assert "release-manifest.json" in source
    assert "Invoke-WebRequest" in source
    assert "MainWindowTitle" in source


def test_build_environment_preparation_is_explicit_and_separate():
    source = (PROJECT_ROOT / "scripts" / "Prepare-BuildEnv.ps1").read_text(
        encoding="utf-8-sig"
    )

    assert ".venv-build" in source
    assert "requirements.build.lock" in source
    assert "scripts/build_app.py" not in source
