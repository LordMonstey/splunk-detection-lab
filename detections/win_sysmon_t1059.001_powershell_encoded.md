---
id: win_sysmon_t1059.001_powershell_encoded
title: PowerShell with encoded command argument
status: testing
author: LordMonstey
created: 2026-04-28
modified: 2026-04-28
severity: high
risk_score: 60
attack:
  - tactic: execution
    technique: T1059.001
    sub_technique_name: PowerShell
data_source:
  index: sysmon
  sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  event_codes: [1]
mitre_data_component: Process Creation
schedule:
  cron: "*/5 * * * *"
  earliest: "-10m@m"
  latest:   "-1m@m"
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe
tags:
  - powershell
  - execution
  - obfuscation
---

## Hypothesis

Adversaries use the `-EncodedCommand` (and shorthand `-enc`, `-e`, `-ec`) parameter of PowerShell to pass Base64-encoded payloads to interpreters, evading signature-based detection. The vast majority of legitimate PowerShell usage on a workstation does not require this parameter; its presence is a strong execution-stage signal when correlated with a non-administrative parent.

## Logic

```spl
`sysmon_process_creation`
(process_name="powershell.exe" OR process_name="pwsh.exe")
CommandLine="*"
| where match(CommandLine, "(?i)\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s")
| eval encoded_blob = mvindex(split(CommandLine, " "), -1)
| eval blob_len = len(encoded_blob)
| `cim_endpoint_processes_rename`
| stats count min(_time) as firstTime max(_time) as lastTime
        values(CommandLine) as commandlines
        values(parent_process_name) as parents
        values(blob_len) as blob_lengths
        by dest user process_name process_guid
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

## Known false positives

- Microsoft Endpoint Configuration Manager (MECM/SCCM) client occasionally invokes encoded PowerShell from `ccmexec.exe` for compliance scripts → allowlisted via parent_process_name in `lookups/allowlist_powershell_encoded.csv`
- Some Windows update routines wrap PowerShell with -EncodedCommand for atomic write operations → low-volume, accepted noise after baseline
- Visual Studio Code remote extensions occasionally emit short encoded payloads — typically <100 chars; tuning option below

## Tuning

- Minimum blob length filter: add `| where blob_lengths > 50` to drop the trivially short encodes
- Allowlist parent processes via `lookups/allowlist_powershell_encoded.csv`
- Suppression: 30 minutes per `(dest, process_guid)` to avoid duplicates from short-lived re-execution

## Validation

- Atomic Red Team: [T1059.001 #2 — Mimikatz via encoded PowerShell](../tests/atomic/T1059.001.md)

Manual reproduction:

```powershell
$cmd = "Write-Host 'atomic-validation-$(Get-Date -Format yyyyMMddHHmmss)'"
$encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -EncodedCommand $encoded
```

## Response

See [`docs/runbooks/powershell-suspicious-execution.md`](../docs/runbooks/powershell-suspicious-execution.md).

Triage priorities:

1. Decode the blob (`[Convert]::FromBase64String` then `[System.Text.Encoding]::Unicode.GetString`) — content is the single most important triage artifact
2. Walk the process tree via `process_guid` for spawned children and outbound network
3. Pivot on parent: `winword.exe`, `excel.exe`, `outlook.exe`, browser → suspected initial access, escalate
4. Search `index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventID=4104 host=<dest>` for the deobfuscated script block (PS module logging)
