from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "v9-portal-image.yml"


def test_portal_image_workflow_is_manual_and_main_bound() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in text
    assert "release_sha:" in text
    assert "if: github.ref == 'refs/heads/main'" in text
    assert "git ls-remote --exit-code origin refs/heads/main" in text
    assert 'test "${GITHUB_SHA}" = "${RELEASE_SHA}"' in text
    assert 'test "${GITHUB_WORKFLOW_SHA}" = "${RELEASE_SHA}"' in text
    assert "GITHUB_WORKFLOW_REF" in text
    assert "v9-portal-image.yml@refs/heads/main" in text
    assert "persist-credentials: false" in text


def test_portal_image_workflow_uses_digest_pinned_inputs_and_actions() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert re.search(
        r"PYTHON_BASE_IMAGE: python:3\.11\.14-slim-bookworm@sha256:[0-9a-f]{64}",
        text,
    )
    uses = re.findall(r"^\s*-?\s*uses:\s*([^\s#]+)", text, flags=re.MULTILINE)
    assert uses
    assert all(re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", item) for item in uses)


def test_portal_image_workflow_pushes_by_explicit_gate_and_attests_digest() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "packages: write" in text
    assert "id-token: write" in text
    assert "attestations: write" in text
    assert "build-portal-image.sh" in text
    assert "--push | tee" in text
    assert "subject-digest: ${{ steps.build.outputs.digest }}" in text
    assert "push-to-registry: true" in text
    assert "gh attestation verify \"oci://${IMAGE_REFERENCE}\"" in text
    assert "--bundle-from-oci" in text
    assert "--source-ref refs/heads/main" in text
    assert '--source-digest "${RELEASE_SHA}"' in text
    assert "--deny-self-hosted-runners" in text
    assert "https://github.com/*/attestations/*" in text
    assert "portal-image.json" in text


def test_portal_image_workflow_does_not_accept_registry_or_base_image_inputs() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    inputs = text.split("permissions:", 1)[0]
    assert "image_repository:" not in inputs
    assert "base_image:" not in inputs
    assert "secrets." not in text
