"""Regenerate (or check) the compliance data integrity manifest.

THREAT_MODEL.md T4. The manifest ``MANIFEST.sha256`` lives next to the
bundled framework YAMLs and records one sha256 per file in ``sha256sum``
format. Run this script after editing any file under
``packages/argos-core/src/argos_core/compliance/data/``::

    uv run python scripts/build_compliance_manifest.py          # rewrite
    uv run python scripts/build_compliance_manifest.py --check  # CI gate

``--check`` exits 1 when the manifest on disk differs from what the
data files produce, without touching the file.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "packages" / "argos-core" / "src"))

from argos_core.compliance.manifest import (  # noqa: E402
    MANIFEST_FILENAME,
    compute_digests,
    render_manifest,
)

DATA_DIR = REPO_ROOT / "packages" / "argos-core" / "src" / "argos_core" / "compliance" / "data"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="Do not write; exit 1 if the manifest is stale.",
    )
    args = parser.parse_args(argv)

    manifest_path = DATA_DIR / MANIFEST_FILENAME
    rendered = render_manifest(compute_digests(DATA_DIR))
    current = manifest_path.read_text(encoding="utf-8") if manifest_path.is_file() else None

    if args.check:
        if current == rendered:
            print(f"[manifest] {manifest_path.relative_to(REPO_ROOT)} is up to date")
            return 0
        print(
            f"[manifest] {manifest_path.relative_to(REPO_ROOT)} is stale; "
            "run scripts/build_compliance_manifest.py and commit the result",
        )
        return 1

    manifest_path.write_text(rendered, encoding="utf-8", newline="\n")
    state = "unchanged" if current == rendered else "written"
    print(f"[manifest] {manifest_path.relative_to(REPO_ROOT)} {state}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
