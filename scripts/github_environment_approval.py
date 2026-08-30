# -*- coding: utf-8 -*-
"""Create and validate a canonical GitHub Environment approval context.

This document binds one protected-environment job to the exact bytes it is
allowed to process.  It deliberately does not claim who approved the GitHub
Environment, prove that a human reviewed the subject, or replace artifact
signing/provenance verification.  Those remain separate GitHub and release
controls.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import unicodedata
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Mapping


ApprovalSubjectKind = Literal["compliance-evidence", "installer-review-request"]

APPROVAL_MODE = "github-environment"
REVIEW_MODEL = "single-maintainer-audited"
SUBJECT_KINDS = frozenset({"compliance-evidence", "installer-review-request"})

SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ENVIRONMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
REPOSITORY_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?$"
)
JOB_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
WORKFLOW_PART_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
REF_RE = re.compile(r"^refs/(?:heads|tags)/[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")
UTC_SECONDS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

_CONTEXT_KEYS = {
    "schema",
    "approval_mode",
    "review_model",
    "environment",
    "repository",
    "workflow_ref",
    "release_commit",
    "run_id",
    "run_attempt",
    "job",
    "subject_kind",
    "subject_sha256",
    "generated_at_utc",
}
_MAX_CONTEXT_BYTES = 16 * 1024
_MAX_POSITIVE_ID = 9_223_372_036_854_775_807


@dataclass(frozen=True)
class ApprovalContext:
    schema: int
    approval_mode: str
    review_model: str
    environment: str
    repository: str
    workflow_ref: str
    release_commit: str
    run_id: int
    run_attempt: int
    job: str
    subject_kind: ApprovalSubjectKind
    subject_sha256: str
    generated_at_utc: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def canonical_json_bytes(value: object) -> bytes:
    """Render canonical UTF-8 JSON with exactly one trailing LF."""

    if isinstance(value, ApprovalContext):
        value = value.as_dict()
    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("Approval context is not JSON-canonicalizable") from exc
    return (rendered + "\n").encode("utf-8")


def sha256_file(path: Path) -> str:
    """Hash a regular file without following a caller-supplied symlink."""

    if path.is_symlink() or not path.is_file():
        raise ValueError("Approval subject must be a regular file")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
            after = os.fstat(stream.fileno())
    except OSError as exc:
        raise ValueError("Approval subject could not be read") from exc
    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ino != after.st_ino
    ):
        raise ValueError("Approval subject changed while it was being hashed")
    return digest.hexdigest()


def _strict_json_loads(payload: bytes) -> object:
    if not payload or len(payload) > _MAX_CONTEXT_BYTES:
        raise ValueError("Approval context has an invalid size")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Approval context is not UTF-8 JSON") from exc

    def reject_constant(value: str) -> object:
        raise ValueError(f"Approval context contains a non-finite number: {value}")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Approval context contains a duplicate key")
            result[key] = value
        return result

    try:
        return json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise ValueError("Approval context is not valid JSON") from exc


def _safe_identifier(value: object, label: str, pattern: re.Pattern[str]) -> str:
    if (
        not isinstance(value, str)
        or value != unicodedata.normalize("NFC", value)
        or pattern.fullmatch(value) is None
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _validate_repository(value: object) -> str:
    if not isinstance(value, str) or value.count("/") != 1:
        raise ValueError("repository is invalid")
    owner, repository = value.split("/", 1)
    if (
        OWNER_RE.fullmatch(owner) is None
        or REPOSITORY_RE.fullmatch(repository) is None
        or repository in {".", ".."}
        or repository.endswith(".git")
        or value != unicodedata.normalize("NFC", value)
    ):
        raise ValueError("repository is invalid")
    return value


def _validate_workflow_ref(value: object, repository: str) -> str:
    if not isinstance(value, str) or value != unicodedata.normalize("NFC", value):
        raise ValueError("workflow_ref is invalid")
    prefix = f"{repository}/.github/workflows/"
    if not value.startswith(prefix) or value.count("@") != 1:
        raise ValueError("workflow_ref is invalid")
    path_text, ref = value[len(prefix) :].split("@", 1)
    path = PurePosixPath(path_text)
    if (
        not path_text.endswith((".yml", ".yaml"))
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(WORKFLOW_PART_RE.fullmatch(part) is None for part in path.parts)
        or (SHA1_RE.fullmatch(ref) is None and REF_RE.fullmatch(ref) is None)
        or "//" in ref
        or "/./" in ref
        or "/../" in ref
        or ref.endswith(("/", "."))
    ):
        raise ValueError("workflow_ref is invalid")
    return value


def _positive_id(value: object, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > _MAX_POSITIVE_ID
    ):
        raise ValueError(f"{label} must be a positive 64-bit integer")
    return value


def _utc_seconds(value: object) -> str:
    if not isinstance(value, str) or UTC_SECONDS_RE.fullmatch(value) is None:
        raise ValueError("generated_at_utc must be canonical UTC seconds")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ValueError("generated_at_utc must be canonical UTC seconds") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ValueError("generated_at_utc must be canonical UTC seconds")
    return value


def validate_approval_context(
    value: Mapping[str, object],
    *,
    expected_environment: str | None = None,
    expected_repository: str | None = None,
    expected_workflow_ref: str | None = None,
    expected_release_commit: str | None = None,
    expected_run_id: int | None = None,
    expected_run_attempt: int | None = None,
    expected_job: str | None = None,
    expected_subject_kind: ApprovalSubjectKind | None = None,
    expected_subject_sha256: str | None = None,
) -> ApprovalContext:
    """Validate schema and optional exact bindings, returning a typed context."""

    if not isinstance(value, Mapping) or set(value) != _CONTEXT_KEYS:
        raise ValueError("Approval context fields differ from schema")
    repository = _validate_repository(value["repository"])
    subject_kind = value["subject_kind"]
    if not isinstance(subject_kind, str) or subject_kind not in SUBJECT_KINDS:
        raise ValueError("subject_kind is invalid")
    schema = value["schema"]
    if isinstance(schema, bool) or not isinstance(schema, int):
        raise ValueError("Approval context schema is unsupported")
    context = ApprovalContext(
        schema=schema,
        approval_mode=str(value["approval_mode"]),
        review_model=str(value["review_model"]),
        environment=_safe_identifier(
            value["environment"], "environment", ENVIRONMENT_RE
        ),
        repository=repository,
        workflow_ref=_validate_workflow_ref(value["workflow_ref"], repository),
        release_commit=_safe_identifier(
            value["release_commit"], "release_commit", SHA1_RE
        ),
        run_id=_positive_id(value["run_id"], "run_id"),
        run_attempt=_positive_id(value["run_attempt"], "run_attempt"),
        job=_safe_identifier(value["job"], "job", JOB_RE),
        subject_kind=subject_kind,  # type: ignore[arg-type]
        subject_sha256=_safe_identifier(
            value["subject_sha256"], "subject_sha256", SHA256_RE
        ),
        generated_at_utc=_utc_seconds(value["generated_at_utc"]),
    )
    if context.schema != 1:
        raise ValueError("Approval context schema is unsupported")
    if context.approval_mode != APPROVAL_MODE:
        raise ValueError("approval_mode is invalid")
    if context.review_model != REVIEW_MODEL:
        raise ValueError("review_model is invalid")

    expected = {
        "environment": expected_environment,
        "repository": expected_repository,
        "workflow_ref": expected_workflow_ref,
        "release_commit": expected_release_commit,
        "run_id": expected_run_id,
        "run_attempt": expected_run_attempt,
        "job": expected_job,
        "subject_kind": expected_subject_kind,
        "subject_sha256": expected_subject_sha256,
    }
    for field, expected_value in expected.items():
        if expected_value is not None and getattr(context, field) != expected_value:
            raise ValueError(f"Approval context {field} does not match the expected value")
    return context


def create_approval_context(
    *,
    environment: str,
    repository: str,
    workflow_ref: str,
    release_commit: str,
    run_id: int,
    run_attempt: int,
    job: str,
    subject_kind: ApprovalSubjectKind,
    subject_sha256: str,
    generated_at_utc: str | None = None,
) -> ApprovalContext:
    """Create a validated context; GitHub supplies the approval itself."""

    if generated_at_utc is None:
        generated_at_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return validate_approval_context(
        {
            "schema": 1,
            "approval_mode": APPROVAL_MODE,
            "review_model": REVIEW_MODEL,
            "environment": environment,
            "repository": repository,
            "workflow_ref": workflow_ref,
            "release_commit": release_commit,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "job": job,
            "subject_kind": subject_kind,
            "subject_sha256": subject_sha256,
            "generated_at_utc": generated_at_utc,
        }
    )


def load_approval_context(
    path: Path,
    **expected: Any,
) -> ApprovalContext:
    """Load an exact canonical context from a regular file and validate it."""

    if path.is_symlink() or not path.is_file():
        raise ValueError("Approval context must be a regular file")
    try:
        with path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            payload = stream.read(_MAX_CONTEXT_BYTES + 1)
            after = os.fstat(stream.fileno())
    except OSError as exc:
        raise ValueError("Approval context could not be read") from exc
    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ino != after.st_ino
    ):
        raise ValueError("Approval context changed while it was being read")
    value = _strict_json_loads(payload)
    if not isinstance(value, dict):
        raise ValueError("Approval context must be a JSON object")
    context = validate_approval_context(value, **expected)
    if payload != canonical_json_bytes(context.as_dict()):
        raise ValueError("Approval context is not canonical JSON")
    return context


def write_approval_context(path: Path, context: ApprovalContext) -> None:
    """Create an immutable-once-written context file without overwriting."""

    validated = validate_approval_context(context.as_dict())
    if path.is_symlink() or not path.parent.is_dir():
        raise ValueError("Approval context output path is unsafe")
    try:
        with path.open("xb") as stream:
            stream.write(canonical_json_bytes(validated.as_dict()))
    except OSError as exc:
        raise ValueError("Approval context output could not be created") from exc


def _positive_cli_id(value: str) -> int:
    try:
        parsed = int(value, 10)
        return _positive_id(parsed, "GitHub run identifier")
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--environment", required=True)
    create.add_argument("--repository", required=True)
    create.add_argument("--workflow-ref", required=True)
    create.add_argument("--release-commit", required=True)
    create.add_argument("--run-id", type=_positive_cli_id, required=True)
    create.add_argument("--run-attempt", type=_positive_cli_id, required=True)
    create.add_argument("--job", required=True)
    create.add_argument("--subject-kind", choices=sorted(SUBJECT_KINDS), required=True)
    subject = create.add_mutually_exclusive_group(required=True)
    subject.add_argument("--subject", type=Path)
    subject.add_argument("--subject-sha256")
    create.add_argument("--generated-at-utc")
    create.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    subject_sha256 = (
        sha256_file(args.subject)
        if args.subject is not None
        else args.subject_sha256
    )
    context = create_approval_context(
        environment=args.environment,
        repository=args.repository,
        workflow_ref=args.workflow_ref,
        release_commit=args.release_commit,
        run_id=args.run_id,
        run_attempt=args.run_attempt,
        job=args.job,
        subject_kind=args.subject_kind,
        subject_sha256=subject_sha256,
        generated_at_utc=args.generated_at_utc,
    )
    write_approval_context(args.output, context)
    print("github-environment-approval: GENERATED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
