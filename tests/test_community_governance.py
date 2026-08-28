"""Public community-governance files must stay explicit and fail closed."""

from pathlib import Path

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (PROJECT_ROOT / path).read_text(encoding="utf-8")


def _normalized(path: str) -> str:
    return " ".join(_read(path).replace("**", "").split())


def test_license_is_complete_agpl_v3_only_text():
    license_text = _read("LICENSE")

    assert "GNU AFFERO GENERAL PUBLIC LICENSE" in license_text
    assert "Version 3, 19 November 2007" in license_text
    assert "13. Remote Network Interaction; Use with the GNU General Public License." in license_text
    assert "END OF TERMS AND CONDITIONS" in license_text
    assert "Source-Visible, All Rights Reserved" not in license_text


def test_public_entrypoints_describe_agpl_and_current_release_boundary():
    readme = _read("README.md")
    public_release = _read("docs/PUBLIC_RELEASE.md")
    notices = _read("THIRD_PARTY_NOTICES.md")

    assert "AGPL-3.0-only" in readme
    assert "AGPL-3.0-only" in public_release
    assert "AGPL-3.0-only" in notices
    assert "green CI run is not evidence" in readme
    assert "not proof that a binary is official" in _normalized("SECURITY.md")
    assert "source-visible and all rights reserved" not in readme.lower()
    assert "not an open-source release" not in public_release.lower()


def test_cla_and_commercial_license_are_fail_closed():
    cla = _read("CLA_POLICY.md")
    commercial = _normalized("COMMERCIAL_LICENSE.md")
    contributing = _normalized("CONTRIBUTING.md")

    assert "INACTIVE — EXTERNAL MERGES BLOCKED" in cla
    assert "must not be merged or cherry-picked" in cla
    assert "does not grant a commercial exception" in commercial
    assert "no commercial-license offer is available" in commercial
    assert "must not merge or cherry-pick" in contributing


def test_data_policy_rejects_private_and_copied_material():
    policy = _read("docs/DATA_CONTRIBUTION_POLICY.md").lower()

    for required in (
        "third-party full text",
        "paywalled",
        "account screenshots",
        "qr codes",
        "personal data",
        "real configuration",
        "suspected internal",
        "local filesystem",
    ):
        assert required in policy


def test_release_policy_requires_trusted_signing_and_immutability():
    policy = _normalized("docs/RELEASE_SIGNING_POLICY.md")

    assert "Microsoft Artifact Signing" in policy
    assert "DigiCert KeyLocker" in policy
    assert "Self-signed" in policy
    assert "RFC 3161" in policy
    assert "GitHub build and SBOM attestation" in policy
    assert "immutable-release enforcement" in policy
    assert "must not move or be deleted" in policy
    assert "v9.0.1" in policy
    assert "stable Windows release is blocked" in policy


def test_required_community_files_and_codeowners_exist():
    required = (
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "GOVERNANCE.md",
        "COMMERCIAL_LICENSE.md",
        "CLA_POLICY.md",
        "docs/COMMUNITY.md",
        ".github/CODEOWNERS",
        ".github/pull_request_template.md",
    )
    for relative_path in required:
        assert (PROJECT_ROOT / relative_path).is_file(), relative_path

    codeowners = _read(".github/CODEOWNERS")
    assert "* @player1314520" in codeowners
    assert "/SECURITY.md @player1314520" in codeowners


def test_issue_forms_are_parseable_and_blank_issues_are_disabled():
    forms_dir = PROJECT_ROOT / ".github" / "ISSUE_TEMPLATE"
    config = yaml.safe_load((forms_dir / "config.yml").read_text(encoding="utf-8"))

    assert config["blank_issues_enabled"] is False
    assert len(config["contact_links"]) >= 2

    form_paths = sorted(path for path in forms_dir.glob("*.yml") if path.name != "config.yml")
    assert {path.name for path in form_paths} >= {
        "bug_report.yml",
        "data_contribution.yml",
        "feature_request.yml",
        "moderation_request.yml",
    }
    for form_path in form_paths:
        form = yaml.safe_load(form_path.read_text(encoding="utf-8"))
        assert form["name"]
        assert form["description"]
        assert isinstance(form["body"], list) and form["body"]


def test_each_policy_states_multiple_honest_boundaries():
    policy_paths = (
        "README.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
        "GOVERNANCE.md",
        "COMMERCIAL_LICENSE.md",
        "CLA_POLICY.md",
        "docs/COMMUNITY.md",
        "docs/DATA_CONTRIBUTION_POLICY.md",
        "docs/PUBLIC_RELEASE.md",
        "docs/RELEASE_SIGNING_POLICY.md",
        "THIRD_PARTY_NOTICES.md",
    )
    for relative_path in policy_paths:
        text = _read(relative_path)
        assert "boundar" in text.lower(), relative_path
