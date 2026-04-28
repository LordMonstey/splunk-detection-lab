---
id: win_sysmon_t1059.003_cmd_obfuscation
title: cmd.exe with caret/quote obfuscation patterns
status: testing
author: LordMonstey
created: 2026-04-28
modified: 2026-04-28
severity: medium
risk_score: 50
attack:
  - tactic: execution
    technique: T1059.003
    sub_technique_name: Windows Command Shell
  - tactic: defense-evasion
    technique: T1027
    sub_technique_name: Obfuscated Files or Information
data_source:
  index: sysmon
  sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  event_codes: [1]
mitre_data_component: Process Creation
schedule:
  cron: "*/10 * * * *"
  earliest: "-15m@m"
  latest:   "-1m@m"
references:
  - https://attack.mitre.org/techniques/T1059/003/
  - https://github.com/danielbohannon/Invoke-DOSfuscation
tags:
  - cmd
  - obfuscation
  - execution
---

## Hypothesis

Adversaries leverage the cmd.exe parser's tolerance for caret (`^`), surrounding quotes, and concatenation tricks (`s^et`, `c^md`, `p^ow^ershell`) to evade string-matching detections. Legitimate command lines virtually never contain caret characters outside of a few specific Windows installers.

## Logic

```spl
`sysmon_process_creation`
process_name="cmd.exe"
| eval caret_count = mvcount(split(CommandLine, "^")) - 1
| where caret_count >= 3
| `cim_endpoint_processes_rename`
| stats count min(_time) as firstTime max(_time) as lastTime
        values(CommandLine) as commandlines
        values(parent_process_name) as parents
        max(caret_count) as max_carets
        by dest user process_name process_guid
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

## Known false positives

- Some legacy build scripts emit caret-escaped command lines for batch concatenation — typically with stable parent (`msbuild.exe`, `make.exe`)
- ipconfig wrapper scripts in older domain logon scripts

## Tuning

- Threshold of 3+ carets is conservative. Drop to 5+ if your environment ships legacy batch tooling.
- Allowlist by parent process via `lookups/allowlist_cmd_obfuscation.csv`
- Suppression: 1 hour per `(dest, process_guid)`

## Validation

- Atomic Red Team: T1059.003 #5 — Obfuscated Command Line

Manual reproduction:

```cmd
c^m^d.exe /c "e^c^h^o atomic-validation"
```

## Response

See [`docs/runbooks/powershell-suspicious-execution.md`](../docs/runbooks/powershell-suspicious-execution.md) — same triage applies.

1. De-obfuscate by stripping `^` characters from CommandLine
2. Pivot on parent — caret-obfuscated cmd from a productivity app is initial-access territory
3. Escalate to L3 if the deobfuscated content references LOLBins or download cradles
