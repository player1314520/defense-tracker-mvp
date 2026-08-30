import hashlib
import json
import shutil
import struct
import sys
from pathlib import Path

import pytest

from scripts.github_environment_approval import (
    create_approval_context,
    write_approval_context,
)
from scripts.installer_review import (
    APPROVAL_ENVIRONMENT,
    APPROVAL_JOB,
    APPROVAL_SUBJECT_KIND,
    canonical_json_bytes,
    generate_installer_review_request,
    main as installer_review_main,
    sha256_bytes,
    verify_installer_after_sign,
    verify_installer_before_sign,
    write_canonical_json,
)


COMMIT = "1" * 40
TREE = "2" * 40
VERSION = "9.0.0"
PUBLISHER = "Example Legal Publisher"
REPOSITORY = "example/defense-tracker"
WORKFLOW_REF = (
    f"{REPOSITORY}/.github/workflows/v9-signed-candidate.yml@refs/heads/main"
)
RUN_ID = 123456789
RUN_ATTEMPT = 2


def _unsigned_pe() -> bytes:
    """Build a minimal AMD64 PE32+ accepted by the strict release parser."""

    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    pe = 0x80
    data[pe : pe + 4] = b"PE\0\0"
    coff = pe + 4
    struct.pack_into("<HHIIIHH", data, coff, 0x8664, 1, 0, 0, 0, 240, 0x0002)
    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 36, 512)  # FileAlignment
    struct.pack_into("<I", data, optional + 56, 4096)  # SizeOfImage
    struct.pack_into("<I", data, optional + 60, 512)  # SizeOfHeaders
    struct.pack_into("<I", data, optional + 108, 16)  # NumberOfRvaAndSizes
    section = optional + 240
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<II", data, section + 16, 512, 512)
    data[512:1024] = bytes((index % 251 for index in range(512)))
    return bytes(data)


def _simulate_authenticode_signing(unsigned_path: Path, signed_path: Path) -> None:
    data = bytearray(unsigned_path.read_bytes())
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    optional = pe + 4 + 20
    checksum = optional + 64
    security_directory = optional + 112 + 4 * 8
    certificate_offset = (len(data) + 7) & ~7
    data.extend(b"\0" * (certificate_offset - len(data)))
    certificate = struct.pack("<IHH", 16, 0x0200, 0x0002) + b"signed!!"
    struct.pack_into("<I", data, checksum, 0xA5A5A5A5)
    struct.pack_into(
        "<II", data, security_directory, certificate_offset, len(certificate)
    )
    data.extend(certificate)
    signed_path.write_bytes(data)


def _write_approval_context(
    request: dict[str, object], approval_context_path: Path
) -> None:
    request_bytes = canonical_json_bytes(request)
    context = create_approval_context(
        environment=APPROVAL_ENVIRONMENT,
        repository=REPOSITORY,
        workflow_ref=WORKFLOW_REF,
        release_commit=COMMIT,
        run_id=RUN_ID,
        run_attempt=RUN_ATTEMPT,
        job=APPROVAL_JOB,
        subject_kind=APPROVAL_SUBJECT_KIND,
        subject_sha256=sha256_bytes(request_bytes),
        generated_at_utc="2026-08-28T01:02:03Z",
    )
    write_approval_context(approval_context_path, context)


def _case(tmp_path: Path) -> dict[str, object]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    unsigned_installer = tmp_path / "unsigned-installer.exe"
    unsigned_installer.write_bytes(_unsigned_pe())
    payload = tmp_path / "payload"
    (payload / "_internal").mkdir(parents=True)
    (payload / "DefenseTracker.exe").write_bytes(b"signed application bytes")
    (payload / "_internal" / "version.json").write_text(
        '{"semantic_version":"9.0.0"}\n', encoding="utf-8"
    )
    signed_application_inventory = tmp_path / "signed-application-inventory.json"
    signed_application_inventory.write_text(
        '{"schema":1,"files":[{"path":"DefenseTracker.exe"}]}\n',
        encoding="utf-8",
    )
    iss = tmp_path / "DefenseTracker.iss"
    iss.write_text("[Setup]\nAppName=DefenseTracker\n", encoding="utf-8")
    iscc = tmp_path / "ISCC.exe"
    iscc.write_bytes(b"pinned ISCC binary")
    seven_zip = tmp_path / "7z.exe"
    seven_zip.write_bytes(b"pinned 7-Zip binary")
    bootstrap_license_text = tmp_path / "INNO-LICENSE.txt"
    bootstrap_license_text.write_text(
        "Inno Setup license text used by the reviewed bootstrap.\n",
        encoding="utf-8",
        newline="\n",
    )

    request = generate_installer_review_request(
        unsigned_installer=unsigned_installer,
        extracted_payload_root=payload,
        signed_application_inventory=signed_application_inventory,
        iss_path=iss,
        iscc_path=iscc,
        iscc_version="Inno Setup 6.4.3",
        seven_zip_path=seven_zip,
        seven_zip_version="7-Zip 25.01",
        bootstrap_license_declared="LicenseRef-Inno-Setup",
        bootstrap_license_concluded="LicenseRef-Inno-Setup",
        bootstrap_copyright_text="Copyright Jordan Russell and contributors",
        bootstrap_license_text_path=bootstrap_license_text,
        release_commit=COMMIT,
        source_tree=TREE,
        version=VERSION,
        publisher=PUBLISHER,
    )
    request_path = tmp_path / "installer-review-request.json"
    write_canonical_json(request_path, request)
    approval_context = tmp_path / "installer-approval-context.json"
    _write_approval_context(request, approval_context)
    verify_args = {
        "request_path": request_path,
        "approval_context_path": approval_context,
        "expected_repository": REPOSITORY,
        "expected_workflow_ref": WORKFLOW_REF,
        "expected_run_id": RUN_ID,
        "expected_run_attempt": RUN_ATTEMPT,
        "unsigned_installer": unsigned_installer,
        "extracted_payload_root": payload,
        "signed_application_inventory": signed_application_inventory,
        "iss_path": iss,
        "iscc_path": iscc,
        "iscc_version": "Inno Setup 6.4.3",
        "seven_zip_path": seven_zip,
        "seven_zip_version": "7-Zip 25.01",
        "bootstrap_license_declared": "LicenseRef-Inno-Setup",
        "bootstrap_license_concluded": "LicenseRef-Inno-Setup",
        "bootstrap_copyright_text": "Copyright Jordan Russell and contributors",
        "bootstrap_license_text_path": bootstrap_license_text,
        "expected_commit": COMMIT,
        "expected_source_tree": TREE,
        "expected_version": VERSION,
        "expected_publisher": PUBLISHER,
    }
    return {
        "request": request,
        "request_path": request_path,
        "approval_context": approval_context,
        "verify_args": verify_args,
        "unsigned_installer": unsigned_installer,
        "payload": payload,
        "bootstrap_license_text": bootstrap_license_text,
    }


def test_request_binds_full_payload_recipe_normalized_pe_and_bootstrap_license(tmp_path):
    case = _case(tmp_path)
    request = case["request"]
    request_bytes = case["request_path"].read_bytes()
    assert request_bytes == canonical_json_bytes(request)
    assert request["release_commit"] == COMMIT
    assert request["source_tree"] == TREE
    assert request["version"] == VERSION
    assert request["publisher"] == PUBLISHER
    assert request["unsigned_installer"]["signature_state"] == "unsigned"
    assert request["unsigned_installer"]["normalized_sha256"]
    version_bytes = (case["payload"] / "_internal" / "version.json").read_bytes()
    assert request["payload_inventory"]["files"] == [
        {
            "path": "_internal/version.json",
            "bytes": len(version_bytes),
            "sha256": hashlib.sha256(version_bytes).hexdigest(),
        },
        {
            "path": "DefenseTracker.exe",
            "bytes": len(b"signed application bytes"),
            "sha256": hashlib.sha256(b"signed application bytes").hexdigest(),
        },
    ]
    assert request["payload_inventory_sha256"] == hashlib.sha256(
        canonical_json_bytes(request["payload_inventory"])
    ).hexdigest()
    assert request["recipe"]["iss_sha256"]
    assert request["recipe"]["iscc_sha256"]
    assert request["recipe"]["seven_zip_sha256"]
    assert request["recipe"]["signed_application_inventory_sha256"]
    assert request["bootstrap_license"]["license_declared"] == "LicenseRef-Inno-Setup"
    assert request["bootstrap_license"]["license_concluded"] == "LicenseRef-Inno-Setup"
    assert request["bootstrap_license"]["license_text"]
    assert request["bootstrap_license"]["license_text_sha256"] == hashlib.sha256(
        request["bootstrap_license"]["license_text"].encode("utf-8")
    ).hexdigest()


@pytest.mark.parametrize("missing", ["request", "approval_context"])
def test_missing_approval_material_fails_closed(tmp_path, missing):
    case = _case(tmp_path)
    args = dict(case["verify_args"])
    args[f"{missing}_path"] = tmp_path / f"missing-{missing}.json"
    with pytest.raises(ValueError, match="must be a regular file"):
        verify_installer_before_sign(**args)


def test_approval_context_subject_must_match_exact_request_bytes(tmp_path):
    case = _case(tmp_path)
    context = json.loads(case["approval_context"].read_text(encoding="utf-8"))
    context["subject_sha256"] = "0" * 64
    write_canonical_json(case["approval_context"], context)
    with pytest.raises(ValueError, match="subject_sha256 does not match"):
        verify_installer_before_sign(**case["verify_args"])


def test_request_change_after_environment_approval_is_rejected(tmp_path):
    case = _case(tmp_path)
    request = dict(case["request"])
    request["recipe"] = dict(request["recipe"])
    request["recipe"]["iscc_version"] = "Inno Setup 6.4.4"
    write_canonical_json(case["request_path"], request)
    with pytest.raises(ValueError, match="subject_sha256 does not match"):
        verify_installer_before_sign(**case["verify_args"])


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("environment", "unprotected", "environment does not match"),
        ("repository", "other/defense-tracker", "repository does not match"),
        (
            "workflow_ref",
            "example/defense-tracker/.github/workflows/other.yml@refs/heads/main",
            "workflow_ref does not match",
        ),
        ("release_commit", "3" * 40, "release_commit does not match"),
        ("run_id", RUN_ID + 1, "run_id does not match"),
        ("run_attempt", RUN_ATTEMPT + 1, "run_attempt does not match"),
        ("job", "other-job", "job does not match"),
        ("subject_kind", "compliance-evidence", "subject_kind does not match"),
    ],
)
def test_approval_context_must_bind_exact_environment_run_and_subject(
    tmp_path, field, value, message
):
    case = _case(tmp_path)
    context = json.loads(case["approval_context"].read_text(encoding="utf-8"))
    context[field] = value
    if field == "repository":
        context["workflow_ref"] = (
            f"{value}/.github/workflows/v9-signed-candidate.yml@refs/heads/main"
        )
    write_canonical_json(case["approval_context"], context)
    with pytest.raises(ValueError, match=message):
        verify_installer_before_sign(**case["verify_args"])


def test_expected_repository_workflow_run_and_attempt_are_fail_closed(tmp_path):
    mutations = {
        "expected_repository": "other/defense-tracker",
        "expected_workflow_ref": (
            f"{REPOSITORY}/.github/workflows/other.yml@refs/heads/main"
        ),
        "expected_run_id": RUN_ID + 1,
        "expected_run_attempt": RUN_ATTEMPT + 1,
    }
    for index, (field, value) in enumerate(mutations.items()):
        case = _case(tmp_path / str(index))
        args = dict(case["verify_args"])
        args[field] = value
        with pytest.raises(ValueError, match="does not match the expected value"):
            verify_installer_before_sign(**args)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("expected_run_id", True),
        ("expected_run_id", 0),
        ("expected_run_attempt", False),
        ("expected_run_attempt", 0),
    ],
)
def test_expected_run_identifiers_require_positive_integers(tmp_path, field, value):
    case = _case(tmp_path)
    args = dict(case["verify_args"])
    args[field] = value
    with pytest.raises(ValueError, match="positive 64-bit integer"):
        verify_installer_before_sign(**args)


def test_exact_approval_context_schema_rejects_extra_field(tmp_path):
    case = _case(tmp_path)
    context = json.loads(case["approval_context"].read_text(encoding="utf-8"))
    context["trigger_actor"] = "must-not-be-trusted-as-approver"
    write_canonical_json(case["approval_context"], context)
    with pytest.raises(ValueError, match="fields differ from schema"):
        verify_installer_before_sign(**case["verify_args"])


def test_noncanonical_approval_context_is_rejected(tmp_path):
    case = _case(tmp_path)
    context = json.loads(case["approval_context"].read_text(encoding="utf-8"))
    case["approval_context"].write_text(
        json.dumps(context, indent=2) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="not canonical JSON"):
        verify_installer_before_sign(**case["verify_args"])


def test_unsigned_installer_bootstrap_tamper_is_rejected(tmp_path):
    case = _case(tmp_path)
    data = bytearray(case["unsigned_installer"].read_bytes())
    data[600] ^= 0x5A
    case["unsigned_installer"].write_bytes(data)
    with pytest.raises(ValueError, match="bytes differ from the reviewed request"):
        verify_installer_before_sign(**case["verify_args"])


@pytest.mark.parametrize("mutation", ["add", "delete", "change"])
def test_pre_sign_payload_add_delete_change_is_rejected(tmp_path, mutation):
    case = _case(tmp_path)
    payload = case["payload"]
    target = payload / "_internal" / "version.json"
    if mutation == "add":
        (payload / "unexpected.dll").write_bytes(b"unexpected")
    elif mutation == "delete":
        target.unlink()
    else:
        target.write_text('{"semantic_version":"tampered"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="payload differs from the reviewed inventory"):
        verify_installer_before_sign(**case["verify_args"])


def test_iss_tool_application_inventory_and_license_tamper_are_rejected(tmp_path):
    mutators = {
        "iss": lambda args: args["iss_path"].write_text("[Setup]\nAppName=Other\n"),
        "iscc": lambda args: args["iscc_path"].write_bytes(b"different iscc"),
        "seven_zip": lambda args: args["seven_zip_path"].write_bytes(b"different 7zip"),
        "application_inventory": lambda args: args[
            "signed_application_inventory"
        ].write_text("{}\n"),
        "license_text": lambda args: args["bootstrap_license_text_path"].write_text(
            "different license text\n"
        ),
    }
    for index, mutator in enumerate(mutators.values()):
        case = _case(tmp_path / str(index))
        mutator(case["verify_args"])
        with pytest.raises(ValueError, match="differs from the reviewed request"):
            verify_installer_before_sign(**case["verify_args"])


def test_unresolved_bootstrap_license_is_rejected(tmp_path):
    case = _case(tmp_path)
    with pytest.raises(ValueError, match="canonical and resolved"):
        generate_installer_review_request(
            **{
                "unsigned_installer": case["verify_args"]["unsigned_installer"],
                "extracted_payload_root": case["verify_args"]["extracted_payload_root"],
                "signed_application_inventory": case["verify_args"][
                    "signed_application_inventory"
                ],
                "iss_path": case["verify_args"]["iss_path"],
                "iscc_path": case["verify_args"]["iscc_path"],
                "iscc_version": case["verify_args"]["iscc_version"],
                "seven_zip_path": case["verify_args"]["seven_zip_path"],
                "seven_zip_version": case["verify_args"]["seven_zip_version"],
                "bootstrap_license_declared": "NOASSERTION",
                "bootstrap_license_concluded": "NONE",
                "bootstrap_copyright_text": case["verify_args"][
                    "bootstrap_copyright_text"
                ],
                "bootstrap_license_text_path": case["verify_args"][
                    "bootstrap_license_text_path"
                ],
                "release_commit": COMMIT,
                "source_tree": TREE,
                "version": VERSION,
                "publisher": PUBLISHER,
            }
        )


@pytest.mark.parametrize("mutation", ["add", "delete", "change"])
def test_post_sign_payload_add_delete_change_is_rejected(tmp_path, mutation):
    case = _case(tmp_path)
    review = verify_installer_before_sign(**case["verify_args"])
    signed = tmp_path / "signed-installer.exe"
    _simulate_authenticode_signing(case["unsigned_installer"], signed)
    extracted_after_sign = tmp_path / "payload-after-sign"
    shutil.copytree(case["payload"], extracted_after_sign)
    target = extracted_after_sign / "_internal" / "version.json"
    if mutation == "add":
        (extracted_after_sign / "unexpected.dll").write_bytes(b"unexpected")
    elif mutation == "delete":
        target.unlink()
    else:
        target.write_text('{"semantic_version":"tampered"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="payload differs from the reviewed inventory"):
        verify_installer_after_sign(
            review,
            signed_installer=signed,
            extracted_payload_root=extracted_after_sign,
        )


def test_valid_simulated_signing_preserves_normalized_digest_and_payload(tmp_path):
    case = _case(tmp_path)
    review = verify_installer_before_sign(**case["verify_args"])
    signed = tmp_path / "signed-installer.exe"
    _simulate_authenticode_signing(case["unsigned_installer"], signed)
    extracted_after_sign = tmp_path / "payload-after-sign"
    shutil.copytree(case["payload"], extracted_after_sign)
    binding = verify_installer_after_sign(
        review,
        signed_installer=signed,
        extracted_payload_root=extracted_after_sign,
    )
    assert review.pre_sign_binding is not None
    assert review.approval_context_sha256 == hashlib.sha256(
        case["approval_context"].read_bytes()
    ).hexdigest()
    assert review.approval_environment == APPROVAL_ENVIRONMENT
    assert review.approval_repository == REPOSITORY
    assert review.approval_workflow_ref == WORKFLOW_REF
    assert review.approval_run_id == RUN_ID
    assert review.approval_run_attempt == RUN_ATTEMPT
    assert review.review_model == "single-maintainer-audited"
    assert binding.phase == "post-sign"
    assert binding.signature_state == "signed"
    assert binding.unsigned_installer_bytes == case["unsigned_installer"].stat().st_size
    assert binding.normalized_sha256 == review.pre_sign_binding.normalized_sha256
    assert (
        binding.payload_inventory_sha256
        == review.pre_sign_binding.payload_inventory_sha256
    )
    assert binding.installer_sha256 != review.pre_sign_binding.installer_sha256


def test_pre_sign_cli_uses_environment_approval_arguments(
    tmp_path, monkeypatch, capsys
):
    case = _case(tmp_path)
    args = case["verify_args"]
    output = tmp_path / "pre-sign-binding.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "installer_review.py",
            "pre-sign",
            "--request",
            str(args["request_path"]),
            "--approval-context",
            str(args["approval_context_path"]),
            "--repository",
            str(args["expected_repository"]),
            "--workflow-ref",
            str(args["expected_workflow_ref"]),
            "--run-id",
            str(args["expected_run_id"]),
            "--run-attempt",
            str(args["expected_run_attempt"]),
            "--unsigned-installer",
            str(args["unsigned_installer"]),
            "--payload-root",
            str(args["extracted_payload_root"]),
            "--signed-application-inventory",
            str(args["signed_application_inventory"]),
            "--iss",
            str(args["iss_path"]),
            "--iscc",
            str(args["iscc_path"]),
            "--iscc-version",
            str(args["iscc_version"]),
            "--seven-zip",
            str(args["seven_zip_path"]),
            "--seven-zip-version",
            str(args["seven_zip_version"]),
            "--bootstrap-license-declared",
            str(args["bootstrap_license_declared"]),
            "--bootstrap-license-concluded",
            str(args["bootstrap_license_concluded"]),
            "--bootstrap-copyright-text",
            str(args["bootstrap_copyright_text"]),
            "--bootstrap-license-text",
            str(args["bootstrap_license_text_path"]),
            "--release-sha",
            str(args["expected_commit"]),
            "--expected-tree",
            str(args["expected_source_tree"]),
            "--expected-version",
            str(args["expected_version"]),
            "--expected-publisher",
            str(args["expected_publisher"]),
            "--output",
            str(output),
        ],
    )
    assert installer_review_main() == 0
    assert capsys.readouterr().out == "installer-review-pre-sign: PASS\n"
    binding = json.loads(output.read_text(encoding="utf-8"))
    assert binding["phase"] == "pre-sign"
    assert binding["signature_state"] == "unsigned"


def test_signed_installer_noncertificate_bootstrap_tamper_is_rejected(tmp_path):
    case = _case(tmp_path)
    review = verify_installer_before_sign(**case["verify_args"])
    signed = tmp_path / "signed-installer.exe"
    _simulate_authenticode_signing(case["unsigned_installer"], signed)
    data = bytearray(signed.read_bytes())
    data[600] ^= 0x01
    signed.write_bytes(data)
    with pytest.raises(ValueError, match="body changed outside Authenticode fields"):
        verify_installer_after_sign(
            review,
            signed_installer=signed,
            extracted_payload_root=case["payload"],
        )
