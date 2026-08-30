# -*- coding: utf-8 -*-
"""Validate exact compliance evidence before a signing Environment is entered."""

from __future__ import annotations

import argparse
import os
from datetime import datetime, timezone
from pathlib import Path

from package_release_assets import load_compliance_evidence
from signing_exchange import write_canonical_json


def _positive_github_id(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "GitHub run identifiers must be positive integers"
        ) from exc
    if parsed < 1 or parsed > 9_223_372_036_854_775_807:
        raise argparse.ArgumentTypeError(
            "GitHub run identifiers must be positive integers"
        )
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--application-signing-request", type=Path, required=True)
    parser.add_argument(
        "--expected-application-signing-request-sha256", required=True
    )
    parser.add_argument("--component-inventory", type=Path, required=True)
    parser.add_argument("--application-root", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--publisher", required=True)
    parser.add_argument("--packages-file", type=Path, required=True)
    parser.add_argument("--third-party-notices", type=Path, required=True)
    parser.add_argument("--runtime-lock-sha256", required=True)
    parser.add_argument("--build-lock-sha256", required=True)
    parser.add_argument("--verified-at-utc", required=True)
    parser.add_argument("--output-receipt", type=Path)
    parser.add_argument(
        "--github-repository",
        default=os.environ.get("GITHUB_REPOSITORY"),
    )
    parser.add_argument(
        "--github-workflow-ref",
        default=os.environ.get("GITHUB_WORKFLOW_REF"),
    )
    parser.add_argument(
        "--github-run-id",
        type=_positive_github_id,
        default=os.environ.get("GITHUB_RUN_ID"),
    )
    parser.add_argument(
        "--github-run-attempt",
        type=_positive_github_id,
        default=os.environ.get("GITHUB_RUN_ATTEMPT"),
    )
    args = parser.parse_args()
    for name, value in (
        ("GITHUB_REPOSITORY", args.github_repository),
        ("GITHUB_WORKFLOW_REF", args.github_workflow_ref),
        ("GITHUB_RUN_ID", args.github_run_id),
        ("GITHUB_RUN_ATTEMPT", args.github_run_attempt),
    ):
        if value is None or value == "":
            parser.error(f"{name} is required")
    try:
        github_run_id = _positive_github_id(str(args.github_run_id))
        github_run_attempt = _positive_github_id(str(args.github_run_attempt))
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))
    _, _, compliance = load_compliance_evidence(
        args.evidence.resolve(),
        application_signing_request_path=args.application_signing_request.resolve(),
        expected_application_signing_request_sha256=(
            args.expected_application_signing_request_sha256
        ),
        component_inventory_file=args.component_inventory.resolve(),
        application_root=args.application_root.resolve(),
        expected_sha256=args.expected_sha256,
        commit=args.commit,
        source_tree=args.source_tree,
        publisher=args.publisher,
        packages_file=args.packages_file.resolve(),
        notices=args.third_party_notices.resolve(),
        runtime_lock_sha256=args.runtime_lock_sha256,
        build_lock_sha256=args.build_lock_sha256,
        verified_at_utc=args.verified_at_utc,
        expected_repository=args.github_repository,
        expected_workflow_ref=args.github_workflow_ref,
        expected_run_id=github_run_id,
        expected_run_attempt=github_run_attempt,
    )
    if args.output_receipt is not None:
        receipt = {
            "schema": 2,
            "kind": "defense-tracker-compliance-dispatch-verification",
            "release_commit": args.commit,
            "source_tree": args.source_tree,
            "publisher": args.publisher,
            "application_signing_request_sha256": (
                args.expected_application_signing_request_sha256
            ),
            "compliance_evidence_sha256": args.expected_sha256,
            "component_inventory_sha256": compliance["component_inventory_sha256"],
            "repository": args.github_repository,
            "workflow_ref": args.github_workflow_ref,
            "run_id": github_run_id,
            "run_attempt": github_run_attempt,
            "verified_at_utc": args.verified_at_utc,
            "generated_at_utc": datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
        }
        write_canonical_json(args.output_receipt.resolve(), receipt)
    print("compliance-evidence-pre-sign: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
