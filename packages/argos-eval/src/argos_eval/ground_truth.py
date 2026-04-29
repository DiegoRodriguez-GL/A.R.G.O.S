"""Ground truth declarations for the lab benchmark.

A ground truth records, for every ``(agent_id, probe_id)`` pair the
runner will exercise, the outcome ARGOS is **expected** to produce.
The Phase 4 metrics pipeline compares predicted versus expected to
build the confusion matrix; therefore the integrity of this file is
the ceiling of the whole evaluation.

Two sources are supported:

- :meth:`GroundTruth.from_lab_agents` infers the matrix from each
  agent's declared :attr:`vulnerability_surface`. This is the default
  used when no YAML is supplied. It keeps the surface-of-truth in the
  agent class (a single place to edit).
- :meth:`GroundTruth.from_yaml` loads a stand-alone YAML file. This is
  what an auditor edits when they want to override an entry without
  touching the Python source. The on-disk file is intentionally
  compact: only the cells the auditor expects to **fire** are listed,
  every other cell defaults to **block**. The file produced by
  :meth:`to_yaml` is the canonical artefact the dissertation cites
  alongside the empirical results.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from argos_eval.lab._base import LabAgent
from argos_eval.report import Outcome


def default_ground_truth_path() -> Path:
    """Filesystem path to the YAML shipped with the wheel.

    The file is the canonical ground truth generated from the lab
    agents' declared vulnerability_surface; auditors override entries
    by editing it (or by providing their own YAML to ``from_yaml``).
    """
    return Path(str(resources.files("argos_eval").joinpath("data", "ground_truth.yaml")))


def default_ground_truth() -> GroundTruth:
    """Load the YAML shipped with the wheel."""
    return GroundTruth.from_yaml(default_ground_truth_path())


# Hard cap on the YAML file size we accept on load. A real ground truth
# is a few KiB; anything larger is either a misconfigured input or an
# attempt to exhaust memory via a tag bomb.
_MAX_GROUND_TRUTH_BYTES = 1 * 1024 * 1024  # 1 MiB

# Maximum number of fire cells allowed. With 6 agents and 20 probes the
# theoretical maximum is 120 entries; we cap an order of magnitude
# higher to leave room for additional probes / agents in later phases
# but still bound aberrant inputs.
_MAX_FIRE_CELLS = 4096


class GroundTruth(BaseModel):
    """Declarative `(agent_id, probe_id) -> Outcome` matrix.

    Cells listed in :attr:`fire_cells` are expected to ``FIRE`` (the
    agent is vulnerable to that probe). Every other cell defaults to
    ``BLOCK``. This compact representation keeps the on-disk file under
    a hundred lines for the canonical lab; verbose forms are wasteful
    and easier to diff badly.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    fire_cells: tuple[tuple[str, str], ...] = Field(
        default_factory=tuple,
        description="Pairs (agent_id, probe_id) that are expected to fire.",
    )
    catalogue_version: str = Field(default="argos-eval/0.0.1", max_length=128)
    note: str = Field(
        default="",
        max_length=1024,
        description="Optional auditor note shipped with the file.",
    )

    @field_validator("fire_cells")
    @classmethod
    def _validate_cells(cls, v: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
        if len(v) > _MAX_FIRE_CELLS:
            msg = f"fire_cells has {len(v)} entries; cap is {_MAX_FIRE_CELLS}"
            raise ValueError(msg)
        seen: set[tuple[str, str]] = set()
        for agent_id, probe_id in v:
            # The tuple-of-strings shape is enforced by Pydantic before
            # this validator runs; we only need to check the
            # business-level invariants (non-empty content + uniqueness).
            if not agent_id.strip():
                msg = f"agent_id must be a non-empty string, got {agent_id!r}"
                raise ValueError(msg)
            if not probe_id.strip():
                msg = f"probe_id must be a non-empty string, got {probe_id!r}"
                raise ValueError(msg)
            if (agent_id, probe_id) in seen:
                msg = f"duplicate fire_cell entry ({agent_id!r}, {probe_id!r})"
                raise ValueError(msg)
            seen.add((agent_id, probe_id))
        return v

    @model_validator(mode="after")
    def _normalise(self) -> GroundTruth:
        # Sort cells so a value-equal GroundTruth always serialises to
        # the same bytes regardless of input order. This is critical
        # for the reproducibility property the runner depends on.
        ordered = tuple(sorted(self.fire_cells))
        if ordered != self.fire_cells:
            object.__setattr__(self, "fire_cells", ordered)
        return self

    # ------------------------------------------------------------------
    # Lookup.
    # ------------------------------------------------------------------
    def expected_for(self, agent_id: str, probe_id: str) -> Outcome:
        """Return the expected outcome for the given pair."""
        if (agent_id, probe_id) in self._cell_set:
            return Outcome.FIRE
        return Outcome.BLOCK

    @property
    def _cell_set(self) -> frozenset[tuple[str, str]]:
        # Pydantic frozen models recompute attributes on each access by
        # default; cache the set on the first call.
        cached: frozenset[tuple[str, str]] | None = self.__dict__.get("_cached_set")
        if cached is None:
            cached = frozenset(self.fire_cells)
            object.__setattr__(self, "_cached_set", cached)
        return cached

    def total_fire_cells(self) -> int:
        return len(self.fire_cells)

    # ------------------------------------------------------------------
    # Validation against live catalogues.
    # ------------------------------------------------------------------
    def validate_against(
        self,
        *,
        known_agents: Iterable[str],
        known_probes: Iterable[str],
    ) -> None:
        """Check that every declared cell references an agent and probe
        that exist. Raises :class:`ValueError` on the first miss.

        Phase 3 calls this before kicking off the runner so a stale
        ground truth fails fast instead of silently scoring zero on
        renamed probes.
        """
        agents = set(known_agents)
        probes = set(known_probes)
        for agent_id, probe_id in self.fire_cells:
            if agent_id not in agents:
                msg = f"ground truth references unknown agent_id {agent_id!r}"
                raise ValueError(msg)
            if probe_id not in probes:
                msg = f"ground truth references unknown probe_id {probe_id!r}"
                raise ValueError(msg)

    # ------------------------------------------------------------------
    # Constructors / serialisers.
    # ------------------------------------------------------------------
    @classmethod
    def from_lab_agents(cls, agents: Sequence[LabAgent]) -> GroundTruth:
        """Default ground truth: every probe in a vulnerable agent's
        declared :attr:`LabAgent.vulnerability_surface` is expected to
        ``FIRE``; every other cell defaults to ``BLOCK``."""
        cells: list[tuple[str, str]] = []
        for agent in agents:
            if not agent.is_vulnerable:
                continue
            cells.extend((agent.agent_id, probe_id) for probe_id in agent.vulnerability_surface)
        return cls(fire_cells=tuple(cells))

    @classmethod
    def from_yaml(cls, path: Path) -> GroundTruth:
        """Load a ground-truth YAML file.

        The file format is:

        .. code-block:: yaml

            schema_version: 1
            catalogue_version: "argos-eval/0.0.1"
            note: "Optional auditor note."
            fire:
              lab.react.vulnerable:
                - ASI02-TOOL-ARG-SMUGGLE
                - ASI02-TOOL-CHAIN-ABUSE
              lab.langgraph.vulnerable:
                - ASI09-IDENT-INTER-AGENT
              lab.memory.vulnerable:
                - ASI01-MEM-PROGRESSIVE
        """
        if not path.is_file():
            msg = f"not a file: {path}"
            raise FileNotFoundError(msg)
        if path.is_symlink():
            msg = f"refusing to follow symbolic link: {path}"
            raise ValueError(msg)
        size = path.stat().st_size
        if size > _MAX_GROUND_TRUTH_BYTES:
            msg = f"{path}: {size} bytes exceeds {_MAX_GROUND_TRUTH_BYTES} cap"
            raise ValueError(msg)
        text = path.read_text(encoding="utf-8-sig")
        try:
            raw = yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            msg = f"{path}: invalid YAML ({exc})"
            raise ValueError(msg) from exc
        # Type-shape errors are surfaced as ValueError to keep a single
        # exception type for "bad ground-truth file"; callers should
        # catch ValueError once and report the message.
        if not isinstance(raw, dict):
            msg = f"{path}: top-level must be a YAML mapping"
            raise ValueError(msg)  # noqa: TRY004

        fire_section = raw.get("fire") or {}
        if not isinstance(fire_section, dict):
            msg = f"{path}: 'fire' must be a mapping of agent -> [probes]"
            raise ValueError(msg)  # noqa: TRY004

        cells: list[tuple[str, str]] = []
        for agent_id, probe_list in fire_section.items():
            if not isinstance(probe_list, list):
                msg = f"{path}: fire[{agent_id!r}] must be a list, got {type(probe_list).__name__}"
                raise ValueError(msg)  # noqa: TRY004
            cells.extend((str(agent_id), str(probe_id)) for probe_id in probe_list)

        return cls(
            schema_version=raw.get("schema_version", 1),
            fire_cells=tuple(cells),
            catalogue_version=str(raw.get("catalogue_version", "argos-eval/0.0.1")),
            note=str(raw.get("note", "")),
        )

    def to_yaml(self, path: Path | None = None) -> str:
        """Serialise to YAML. When ``path`` is given the file is also
        written to disk. Returns the rendered text either way so the
        CLI can echo it on stdout."""
        # Group cells by agent for the compact form.
        by_agent: dict[str, list[str]] = {}
        for agent_id, probe_id in self.fire_cells:
            by_agent.setdefault(agent_id, []).append(probe_id)
        for probes in by_agent.values():
            probes.sort()

        document = {
            "schema_version": self.schema_version,
            "catalogue_version": self.catalogue_version,
            "note": self.note or _DEFAULT_NOTE,
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "fire": dict(sorted(by_agent.items())),
        }
        rendered = yaml.safe_dump(
            document,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=False,
        )
        if path is not None:
            path.write_text(rendered, encoding="utf-8")
        return rendered


_DEFAULT_NOTE = (
    "Generated from the lab agents' declared vulnerability_surface. "
    "Edit by hand to override individual cells; the runner uses this "
    "file as the source of truth, not the surface declarations."
)
