"""Load bundled compliance data (frameworks + cross-framework mapping)."""

from __future__ import annotations

import warnings
from functools import lru_cache
from importlib import resources
from typing import Any

import yaml

from argos_core.compliance.manifest import ComplianceIntegrityWarning, verify_manifest
from argos_core.compliance.models import (
    Control,
    ControlIndex,
    FrameworkData,
    FrameworkId,
    FrameworkMeta,
    Mapping,
)

_KNOWN_FRAMEWORKS: tuple[FrameworkId, ...] = (
    "owasp_asi",
    "csa_aicm",
    "eu_ai_act",
    "nist_ai_rmf",
    "iso_42001",
)


def _read_yaml(resource_path: Any) -> Any:
    return yaml.safe_load(resource_path.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def load_controls() -> ControlIndex:
    """Aggregate every bundled framework file and the mapping into a single index.

    Tolerates missing files: if no framework is shipped yet (pre-M1) the index
    is returned empty. Malformed files raise ``ValueError`` loudly.

    Before parsing, the bundled data is checked against its integrity
    manifest (THREAT_MODEL.md T4). Drift does not abort the load -- an
    auditor may be working on the data deliberately -- but it raises a
    :class:`ComplianceIntegrityWarning` so the condition is visible in
    logs and fails any test suite that treats warnings as errors.
    ``argos compliance verify`` exposes the same check as an exit code.
    """
    data_root = resources.files("argos_core.compliance") / "data"
    verification = verify_manifest(data_root)
    if not verification.ok:
        warnings.warn(verification.summary(), ComplianceIntegrityWarning, stacklevel=2)

    framework_metas: list[FrameworkMeta] = []
    controls: list[Control] = []
    for fid in _KNOWN_FRAMEWORKS:
        path = data_root / f"{fid}.yaml"
        if not path.is_file():
            continue
        raw = _read_yaml(path)
        framework = FrameworkData.model_validate(raw)
        if framework.meta.id != fid:
            raise ValueError(
                f"{fid}.yaml declares meta.id={framework.meta.id!r}; expected {fid!r}",
            )
        framework_metas.append(framework.meta)
        controls.extend(framework.controls)

    mapping_path = data_root / "mapping.yaml"
    mapping = None
    if mapping_path.is_file():
        mapping = Mapping.model_validate(_read_yaml(mapping_path))

    return ControlIndex(
        frameworks=tuple(framework_metas),
        controls=tuple(controls),
        mapping=mapping,
    )
