"""Integrity manifest for the bundled compliance data.

THREAT_MODEL.md T4: the YAML files under ``argos_core/compliance/data``
are the ground truth every report maps findings against. If they are
edited on the auditor's machine (by mistake, by a hostile package that
shares the site-packages directory, or by a tampered wheel) every
cross-framework guarantee silently disappears.

The defence is a plain ``MANIFEST.sha256`` shipped next to the data
files, in the ``sha256sum`` text format so it can be checked with
standard tooling::

    cd packages/argos-core/src/argos_core/compliance/data
    sha256sum --check MANIFEST.sha256

At runtime :func:`verify_manifest` recomputes every digest and reports
mismatches, missing files and files present on disk but absent from
the manifest. :func:`argos_core.compliance.load_controls` calls it and
emits :class:`ComplianceIntegrityWarning` on drift; ``argos compliance
verify`` exits non-zero so a CI pipeline can gate on it.

The manifest is regenerated with ``scripts/build_compliance_manifest.py``
and its consistency with the shipped data is itself pinned by a test,
so a data change without a manifest update fails the build.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from importlib import resources
from importlib.resources.abc import Traversable
from typing import Final

MANIFEST_FILENAME: Final[str] = "MANIFEST.sha256"

#: Only these files are covered. Anything else under ``data/`` (editor
#: swap files, ``__pycache__``) is ignored so the check stays stable.
_DATA_SUFFIXES: Final[frozenset[str]] = frozenset({".yaml", ".yml"})

_HEX_DIGITS: Final[frozenset[str]] = frozenset("0123456789abcdef")


class ComplianceIntegrityWarning(RuntimeWarning):
    """Emitted when the bundled compliance data does not match its manifest."""


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of :func:`verify_manifest`.

    ``ok`` is True only when the manifest exists, every listed file is
    present with the recorded digest, and no data file is unlisted.
    """

    manifest_present: bool
    checked: tuple[str, ...]
    mismatched: tuple[str, ...]
    missing: tuple[str, ...]
    unlisted: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return (
            self.manifest_present and not self.mismatched and not self.missing and not self.unlisted
        )

    def summary(self) -> str:
        """One-line human summary suitable for CLI output and warnings."""
        if not self.manifest_present:
            return f"{MANIFEST_FILENAME} not found next to the compliance data"
        if self.ok:
            return f"{len(self.checked)} compliance data files match {MANIFEST_FILENAME}"
        parts: list[str] = []
        if self.mismatched:
            parts.append(f"modified: {', '.join(self.mismatched)}")
        if self.missing:
            parts.append(f"missing: {', '.join(self.missing)}")
        if self.unlisted:
            parts.append(f"unlisted: {', '.join(self.unlisted)}")
        return "compliance data drifted from manifest (" + "; ".join(parts) + ")"


def default_data_root() -> Traversable:
    """The ``data/`` directory shipped inside the ``argos_core`` wheel."""
    return resources.files("argos_core.compliance") / "data"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_digests(data_root: Traversable | None = None) -> dict[str, str]:
    """Return ``{filename: sha256hex}`` for every data file under ``data_root``.

    Filenames are bare (no directory component) because the manifest
    lives in the same directory as the files it covers.
    """
    root = data_root if data_root is not None else default_data_root()
    digests: dict[str, str] = {}
    for entry in root.iterdir():
        if not entry.is_file():
            continue
        name = entry.name
        if not any(name.endswith(suffix) for suffix in _DATA_SUFFIXES):
            continue
        digests[name] = _sha256(entry.read_bytes())
    return dict(sorted(digests.items()))


def render_manifest(digests: dict[str, str]) -> str:
    """Serialise digests in ``sha256sum`` format (two spaces, sorted)."""
    lines = [f"{digest}  {name}" for name, digest in sorted(digests.items())]
    return "\n".join(lines) + "\n"


def parse_manifest(text: str) -> dict[str, str]:
    """Parse ``sha256sum``-style text. Blank lines and ``#`` comments are ignored.

    Raises ``ValueError`` on a malformed line so a corrupted manifest is
    reported loudly instead of silently verifying nothing.
    """
    digests: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            msg = f"{MANIFEST_FILENAME}:{lineno}: expected '<sha256>  <file>', got {raw!r}"
            raise ValueError(msg)
        digest, name = parts
        # sha256sum prefixes binary-mode entries with '*'.
        name = name.lstrip("*").strip()
        digest = digest.lower()
        if len(digest) != 64 or any(c not in _HEX_DIGITS for c in digest):
            msg = f"{MANIFEST_FILENAME}:{lineno}: {digest!r} is not a sha256 hex digest"
            raise ValueError(msg)
        if "/" in name or "\\" in name or name in {"", ".", ".."}:
            msg = f"{MANIFEST_FILENAME}:{lineno}: refusing path component in {name!r}"
            raise ValueError(msg)
        digests[name] = digest
    return digests


def read_manifest(data_root: Traversable | None = None) -> dict[str, str] | None:
    """Load the manifest next to the data files, or ``None`` when absent."""
    root = data_root if data_root is not None else default_data_root()
    path = root / MANIFEST_FILENAME
    if not path.is_file():
        return None
    return parse_manifest(path.read_text(encoding="utf-8"))


def verify_manifest(data_root: Traversable | None = None) -> VerificationResult:
    """Recompute every digest and compare against the shipped manifest."""
    root = data_root if data_root is not None else default_data_root()
    expected = read_manifest(root)
    if expected is None:
        return VerificationResult(
            manifest_present=False,
            checked=(),
            mismatched=(),
            missing=(),
            unlisted=(),
        )
    actual = compute_digests(root)
    mismatched = tuple(
        sorted(
            name for name, digest in expected.items() if name in actual and actual[name] != digest
        ),
    )
    missing = tuple(sorted(name for name in expected if name not in actual))
    unlisted = tuple(sorted(name for name in actual if name not in expected))
    checked = tuple(sorted(name for name in expected if name in actual))
    return VerificationResult(
        manifest_present=True,
        checked=checked,
        mismatched=mismatched,
        missing=missing,
        unlisted=unlisted,
    )


__all__ = [
    "MANIFEST_FILENAME",
    "ComplianceIntegrityWarning",
    "VerificationResult",
    "compute_digests",
    "default_data_root",
    "parse_manifest",
    "read_manifest",
    "render_manifest",
    "verify_manifest",
]
