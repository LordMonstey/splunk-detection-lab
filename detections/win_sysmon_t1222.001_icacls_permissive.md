---
id: win_sysmon_t1222.001_icacls_permissive
title: icacls.exe granting Everyone or world-writable on sensitive paths
status: testing
author: LordMonstey
created: 2026-04-28
modified: 2026-04-28
severity: medium
risk_score: 45
attack:
  - tactic: defense-evasion
    technique: T1222.001
    sub_technique_name: Windows File and Directory Permissions Modification
data_source:
  index: sysmon
  sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  event_codes: [1]
mitre_data_component: Process Creation
schedule:
  cron: "*/15 * * * *"
  earliest: "-20m@m"
  latest:   "-1m@m"
references:
  - https://attack.mitre.org/techniques/T1222/001/
tags:
  - defense-evasion
  - permissions
---

## Hypothesis

Adversaries weaken permissions on directories where they stage tooling (often `%TEMP%`, `%PROGRAMDATA%`, web roots) so that lower-privileged processes can drop or modify files there. Granting `Everyone:(F)` or `BUILTIN\Users:(F)` via `icacls` on these locations is rarely benign on a workstation.

## Logic

```spl
`sysmon_process_creation`
process_name="icacls.exe"
| where match(CommandLine, "(?i)/grant.*\b(everyone|users|authenticated\s*users|domain\s*users):\s*\(?[FM]\)?")
   OR match(CommandLine, "(?i)/grant.*\bs-1-1-0:") 
| `cim_endpoint_processes_rename`
| stats count min(_time) as firstTime max(_time) as lastTime
        values(CommandLine) as commandlines
        values(parent_process_name) as parents
        by dest user process_name process_guid
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

## Known false positives

- Vendor installers calling `icacls` during install (rare on Everyone:F, more common on Users:M)
- IT scripted permission resets

## Tuning

- The `(F)` (full) modifier is the strong signal; `(M)` (modify) is more ambiguous
- Allowlist by `(parent_process_name, target_path)`
- Suppression: 1 hour per `(dest, process_guid)`

## Validation

- Atomic Red Team: T1222.001 #1 — icacls grant Everyone full

Manual reproduction:

```cmd
mkdir C:\AtomicTest
icacls C:\AtomicTest /grant Everyone:(F)
icacls C:\AtomicTest
```

Cleanup:

```cmd
rmdir C:\AtomicTest
```

## Response

See [`docs/runbooks/defense-evasion.md`](../docs/runbooks/defense-evasion.md).

1. Identify the path being relaxed; check what is staged there in the same hour
2. Combine with file-create signals on the same path → suspect staging
3. Pivot on the user account; revert the ACL via `icacls /reset` once investigation is closed
