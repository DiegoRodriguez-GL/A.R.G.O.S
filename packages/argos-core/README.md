# argos-core

Shared types and interfaces for every ARGOS module.

`argos-core` sits at the bottom of the dependency graph: nothing inside this
package imports any other `argos-*` package. If a type is exchanged between
scanner, red-team, proxy or reporter it belongs here.

## Public surface

| Symbol                           | Purpose                                              |
| -------------------------------- | ---------------------------------------------------- |
| `Severity`                       | Ordered severity enum (`INFO < LOW < ... < CRITICAL`)|
| `Target`, `TargetKind`           | Descriptor of the entity being audited               |
| `Evidence`                       | Self-contained artefact supporting a finding         |
| `Finding`, `FindingId`           | Atomic detection unit                                |
| `ScanResult`                     | Run envelope consumed by reporters                   |
| `AutonomyLevel`, `cbra_score`    | CSA L0-L5 taxonomy + risk attribution formula        |
| `IPlugin`, `PluginMetadata`      | Root plugin contract                                 |
| `IScanner`, `IProbe`, `IDetector`, `IReporter` | Per-role abstract interfaces            |
| `ControlIndex`, `load_controls`  | Compliance-data loader (data ships with Module 1)    |
| `init_telemetry`                 | OpenTelemetry bootstrap                              |

## Installation

```bash
uv pip install argos-core
```

## License

AGPL-3.0-or-later. See the repository root `LICENSE`.
