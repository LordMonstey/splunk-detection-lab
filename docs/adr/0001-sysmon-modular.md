# ADR 0001 — Sysmon-modular over SwiftOnSecurity

- **Status**: Accepted
- **Date**: 2025-04-27
- **Decision-maker**: Lab maintainer
- **Supersedes**: —

## Context

The Windows endpoint requires a Sysmon configuration that:

1. Provides high-fidelity process, network, image-load, and registry telemetry
2. Stays maintainable as new MITRE techniques are added to the detection backlog
3. Excludes high-volume noise (e.g., Windows Defender's own scanning, browser cache writes) without silencing genuinely interesting events
4. Can be diff-reviewed when updated

Two community baselines were considered: the **SwiftOnSecurity** monolithic configuration and **Olaf Hartong's sysmon-modular**.

## Decision

Adopt **sysmon-modular** as the upstream and ship the merged result as `conf/sysmon/sysmonconfig.xml`, pinned to a specific upstream commit.

## Rationale

| Criterion | SwiftOnSecurity | sysmon-modular |
|---|---|---|
| Maintainability | Single ~3000-line XML; merges are painful | Per-event-id, per-technique fragments; trivial to diff |
| ATT&CK alignment | Implicit, scattered comments | Explicit `<RuleGroup>` per technique with technique IDs in fragment filenames |
| Update cadence | Slower, mostly Tim Brown solo | Active community + Olaf Hartong; tracks new LOLBins quickly |
| Tunability | Edit-in-place a giant file | Disable/enable fragments by file presence |
| Build process | None (use as-is) | `Merge-SysmonXml.ps1` produces a deterministic output |
| Initial noise | Lower out-of-the-box | Slightly noisier; expected, mitigated by exclusion fragments |

For a lab whose explicit goal is detection engineering, the maintainability and ATT&CK-fragment alignment of sysmon-modular outweigh its higher default verbosity. Noise is a tractable problem; an unmaintainable config is not.

## Consequences

### Positive

- Detection authors can point to the exact Sysmon fragment that produces the field they rely on (traceable telemetry)
- Adding coverage for a new technique is a single-file change (a new exclusion / inclusion fragment)
- Upstream commit pin makes the configuration reproducible

### Negative / accepted trade-offs

- Higher initial event volume; first 48 hours after deployment require a noise-tuning pass
- Build step required (`Merge-SysmonXml.ps1` from the upstream repo) — captured in `scripts/build-sysmon-config.ps1`

## Implementation

- Upstream: <https://github.com/olafhartong/sysmon-modular>
- Pinned commit: `<TODO: paste commit hash after first build>`
- Merged output committed at `conf/sysmon/sysmonconfig.xml`
- Build script: `scripts/build-sysmon-config.ps1`
- Deployment: documented in `docs/install-windows-endpoint.md`

## Validation

After deployment, the following must hold:

```spl
`sysmon_process_creation` | stats count by host
`sysmon_network_connection` | stats count by host
`sysmon_image_load` | stats count by host
`sysmon_registry_event` | stats count by host
```

All four must return non-zero counts within 15 minutes of forwarder start.

## References

- Olaf Hartong, *sysmon-modular*: <https://github.com/olafhartong/sysmon-modular>
- SwiftOnSecurity, *sysmon-config*: <https://github.com/SwiftOnSecurity/sysmon-config>
- Sysmon documentation: <https://learn.microsoft.com/sysinternals/downloads/sysmon>
