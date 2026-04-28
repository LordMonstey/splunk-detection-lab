# Production Gap

What this lab does well, and what would have to change before any of it ran in a real SOC. The intent here is not to pad the README — it is to be honest about scope, because pretending a single-host lab is production-ready is the fastest way to lose credibility in an interview.

## What translates directly

- Detection-as-code workflow, file format, and review process
- Macro-based abstraction (`sysmon_process_creation` etc.) — same approach used in production Splunk apps
- ATT&CK-mapped detections with documented FPs and tuning strategy
- Atomic Red Team validation as a gate for `testing → production` promotion

## What would change

### Telemetry coverage

| Lab | Production |
|---|---|
| Sysmon + native event log only | Sysmon + EDR (CrowdStrike / Defender for Endpoint / SentinelOne) + DNS + proxy + firewall + cloud audit |
| One Windows host | Tens of thousands; tiered onboarding via deployment server / Cribl |
| No network telemetry | Zeek or NDR feeding `index=netflow` / `index=zeek` |
| No identity context beyond a hand-edited `identity.csv` | Live AD / IdP feed populating `identity_lookup`, refreshed hourly |
| No CTI | TI feeds via threat intel framework, IOC hits enriching alerts |

### Architecture

- **Indexer cluster** instead of a single indexer — replication factor and search factor planned around RF=2 / SF=2 minimum
- **Search head cluster** with captain election when more than two analysts are on the platform
- **Heavy forwarders** (or Cribl Stream) in front of the indexers for routing, masking, and protocol translation
- **SmartStore** with S3 / Azure Blob backing for cold buckets — retention extended to 13 months at far lower cost
- **Deployment server** pushing UF configs (the `conf/uf/` directory becomes a deployment app, not a manual copy)

### Detection lifecycle

- Saved searches not edited in `local/` directly — they live in a Splunk app, version-controlled, deployed via CI/CD
- Promotion from `testing` to `production` gated by a peer review and an FP rate threshold measured over 7 days against `index=risk`
- Quarterly purple-team campaigns rather than ad-hoc Atomic runs
- Detection deprecation process — rules with zero TPs in 6 months are reviewed for removal

### Alerting & response

- `index=notable` becomes the Enterprise Security notable index (or an Elasticsearch / Sentinel equivalent)
- Risk-Based Alerting wired to ES Risk Analysis framework, not the manual `risk` index used here
- SOAR (Phantom / XSOAR / Tines) playbooks corresponding to every runbook in `docs/runbooks/`
- Pager / on-call rotation tied to severity, not single-person triage

### Compliance & access

- RBAC: separate roles for analysts, detection authors, and admins; per-index access controls
- Audit trail on saved-search modifications
- Data masking at indexing time for PII-bearing sourcetypes
- Backups and disaster recovery procedures

## Why this matters

A production SOC platform is not a lab plus more hosts; it is a different system with different failure modes (pipeline backpressure, schedule contention, search head load, license accounting, ingestion lag). The work in this lab is the *content* that runs on top of that platform. Knowing the difference is part of the L2/L3 → senior transition.
