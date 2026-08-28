# -*- coding: utf-8 -*-
"""Validate signed legal/compliance evidence before any release signature."""

from __future__ import annotations

import argparse
from pathlib import Path

from package_release_assets import load_compliance_evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--evidence-signature", type=Path, required=True)
    parser.add_argument("--reviewer-registry", type=Path, required=True)
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
    args = parser.parse_args()
    load_compliance_evidence(
        args.evidence.resolve(),
        signature_path=args.evidence_signature.resolve(),
        reviewer_registry=args.reviewer_registry.resolve(),
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
    )
    print("compliance-evidence-pre-sign: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
