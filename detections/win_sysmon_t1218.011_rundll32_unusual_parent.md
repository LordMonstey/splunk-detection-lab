---
id: win_sysmon_t1218.011_rundll32_unusual_parent
title: Rundll32.exe with non-baseline parent or no DLL argument
status: production
author: LordMonstey
created: 2026-04-28
modified: 2026-04-28
severity: high
risk_score: 65
attack:
  - tactic: defense-evasion
    technique: T1218.011
    sub_technique_name: Rundll32
data_source:
  index: sysmon
  sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  event_codes: [1]
mitre_data_component: Process Creation
schedule:
  cron: "*/5 * * * *"
  earliest: "-10m@m"
  latest: "-1m@m"
references:
  - https://attack.mitre.org/techniques/T1218/011/
  - https://lolbas-project.github.io/lolbas/Binaries/Rundll32/
tags:
  - lolbin
  - defense-evasion
  - windows
---

## Hypothesis

`rundll32.exe` is a Microsoft-signed binary used to execute exported functions from DLLs. Adversaries proxy malicious code through it to bypass naive process-based allowlisting. Legitimate `rundll32` is overwhelmingly invoked by `explorer.exe` or `services.exe` and always with a `.dll` argument; deviations from this baseline are suspicious.

## Logic

```spl
`sysmon_process_creation` Image="*\\rundll32.exe" | eval parent_name = mvindex(split(ParentImage,"\\"), -1) | where NOT match(parent_name, "(?i)^(explorer|services|svchost|taskhost|wininit|userinit|sihost|searchindexer)\\.exe$") OR NOT match(CommandLine, "(?i)\\.dll") OR match(CommandLine, "(?i)javascript:|mshtml.*RunHTMLApplication") | `cim_endpoint_processes_rename` | stats count min(_time) as firstTime max(_time) as lastTime values(CommandLine) as commandlines values(parent_process_name) as parents by dest user process_name process_guid
```

## Known false positives

- Microsoft Office repair routines occasionally invoke `rundll32` with no `.dll` from `setup.exe` parents → candidate entries for `lookups/allowlist_rundll32.csv`
- Endpoint management agents (`ccmexec.exe`, `MsiExec.exe` during install) → review against the parent baseline
- `shell32.dll,Control_RunDLL` from explorer is benign — already excluded by parent baseline

## Tuning

- `lookups/allowlist_rundll32.csv` records reviewed tuning candidates keyed on
  `parent_process_name`; it is not invoked by the deployed saved search yet.
- Suppression: 1 hour per `(dest, parent_process_name)`

## Validation

- Atomic Red Team: T1218.011 #1 — `rundll32.exe javascript:`

Manual reproduction:

```cmd
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("calc.exe")
```


**Validated**: 2026-04-29 by manual reproduction on an isolated Windows lab endpoint.
**Public evidence**: [aggregate validation report](../artifacts/public/live-detection-validation-20260806.json). Dispatch completed without error; no positive scenario is claimed for that published campaign.
**Latency observed**: < 30 seconds

## Response

See [`docs/runbooks/lolbin-proxy-execution.md`](../docs/runbooks/lolbin-proxy-execution.md).
