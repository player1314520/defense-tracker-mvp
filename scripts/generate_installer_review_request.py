# -*- coding: utf-8 -*-
"""Generate, but never approve, a canonical installer review request.

The output contains only relative payload paths, hashes, public license text,
and release identifiers.  It cannot verify Authenticode trust, authorize a
reviewer, or replace installation/runtime smoke tests; those are separate
release gates.
"""

from __future__ import annotations

import argparse
from pathlib import Path

try:
    from scripts.installer_review import (
        generate_installer_review_request,
        write_canonical_json,
    )
except ModuleNotFoundError:  # pragma: no cover - direct script execution
    from installer_review import (  # type: ignore[no-redef]
        generate_installer_review_request,
        write_canonical_json,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--unsigned-installer", type=Path, required=True)
    parser.add_argument("--payload-root", type=Path, required=True)
    parser.add_argument("--signed-application-inventory", type=Path, required=True)
    parser.add_argument("--iss", type=Path, required=True)
    parser.add_argument("--iscc", type=Path, required=True)
    parser.add_argument("--iscc-version", required=True)
    parser.add_argument("--seven-zip", type=Path, required=True)
    parser.add_argument("--seven-zip-version", required=True)
    parser.add_argument("--bootstrap-license-declared", required=True)
    parser.add_argument("--bootstrap-license-concluded", required=True)
    parser.add_argument("--bootstrap-copyright-text", required=True)
    parser.add_argument("--bootstrap-license-text", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--publisher", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    request = generate_installer_review_request(
        unsigned_installer=args.unsigned_installer,
        extracted_payload_root=args.payload_root,
        signed_application_inventory=args.signed_application_inventory,
        iss_path=args.iss,
        iscc_path=args.iscc,
        iscc_version=args.iscc_version,
        seven_zip_path=args.seven_zip,
        seven_zip_version=args.seven_zip_version,
        bootstrap_license_declared=args.bootstrap_license_declared,
        bootstrap_license_concluded=args.bootstrap_license_concluded,
        bootstrap_copyright_text=args.bootstrap_copyright_text,
        bootstrap_license_text_path=args.bootstrap_license_text,
        release_commit=args.commit,
        source_tree=args.source_tree,
        version=args.version,
        publisher=args.publisher,
    )
    write_canonical_json(args.output, request)
    print("installer-review-request: GENERATED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
