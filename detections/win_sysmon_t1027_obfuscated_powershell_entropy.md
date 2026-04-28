---
id: win_sysmon_t1027_obfuscated_powershell_entropy
title: PowerShell command line with high character-class entropy
status: testing
author: LordMonstey
created: 2026-04-28
modified: 2026-04-28
severity: medium
risk_score: 50
attack:
  - tactic: defense-evasion
    technique: T1027
    sub_technique_name: Obfuscated Files or Information
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
  - https://attack.mitre.org/techniques/T1027/
  - https://github.com/danielbohannon/Invoke-Obfuscation
tags:
  - powershell
  - obfuscation
  - defense-evasion
---

## Hypothesis

Obfuscated PowerShell exhibits unusual character distributions: very long lines, unusual non-alphanumeric ratios, frequent backticks, escaped tokens, and concatenations like `'In'+'voke'`. A simple proxy for this is the count of "weird" characters per character-length unit — high values are anomalous.

## Logic

```spl
`sysmon_process_creation`
(process_name="powershell.exe" OR process_name="pwsh.exe")
| eval cmd_len = len(CommandLine)
| eval weird_chars = mvcount(split(CommandLine, "`")) - 1
                   + mvcount(split(CommandLine, "+")) - 1
                   + mvcount(split(CommandLine, "$")) - 1
                   + mvcount(split(CommandLine, "{")) - 1
                   + mvcount(split(CommandLine, "}")) - 1
| eval weird_ratio = round((weird_chars / cmd_len) * 100, 2)
| where cmd_len > 200 AND weird_ratio > 8
| `cim_endpoint_processes_rename`
| stats count min(_time) as firstTime max(_time) as lastTime
        values(CommandLine) as commandlines
        max(cmd_len) as cmd_length
        max(weird_ratio) as weirdness_pct
        by dest user process_name process_guid
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

## Known false positives

- Very long benign one-liners with templated JSON or environment variable expansion can trigger
- Some build orchestration tooling (Azure DevOps inline tasks) emits long PowerShell with heavy `$` density — allowlist by parent chain in `lookups/allowlist_pwsh_long.csv`

## Tuning

- The 8% weird-ratio threshold is environment-specific; baseline it for a week before promoting to production
- Combine with the encoded-command detection (T1059.001) — overlap is not a problem, the joint hit raises confidence
- Suppression: 1 hour per `(dest, process_guid)`

## Validation

- Atomic Red Team: T1027 #4 — Obfuscated PowerShell payload (Invoke-Obfuscation)

Manual reproduction:

```powershell
$a='Wri'+'te'; $b='-Ho'+'st'; $c='at'+'omic'+'-test'; & ($a + $b) $c
```

## Response

See [`docs/runbooks/powershell-suspicious-execution.md`](../docs/runbooks/powershell-suspicious-execution.md).

This is a probabilistic detection — expect noise, expect to tune. Investigation priority depends on parent process and account privilege.
