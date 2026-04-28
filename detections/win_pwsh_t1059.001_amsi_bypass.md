---
id: win_pwsh_t1059.001_amsi_bypass
title: PowerShell script block referencing AMSI bypass primitives
status: testing
author: LordMonstey
created: 2026-04-28
modified: 2026-04-28
severity: high
risk_score: 75
attack:
  - tactic: execution
    technique: T1059.001
    sub_technique_name: PowerShell
  - tactic: defense-evasion
    technique: T1562.001
    sub_technique_name: Disable or Modify Tools
data_source:
  index: windows
  sourcetype: XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  event_codes: [4104]
mitre_data_component: Script Block Logging
schedule:
  cron: "*/5 * * * *"
  earliest: "-10m@m"
  latest:   "-1m@m"
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://docs.microsoft.com/en-us/powershell/scripting/learn/deep-dives/security/windows-amsi-features
tags:
  - powershell
  - amsi
  - defense-evasion
---

## Hypothesis

The Antimalware Scan Interface (AMSI) is the primary in-memory inspection point for PowerShell. Bypass techniques are well-known and follow recognizable patterns: reflective access to `System.Management.Automation.AmsiUtils`, manipulation of the `amsiInitFailed` field, and DLL patches via `VirtualProtect`. Script Block Logging (EID 4104) captures the full deobfuscated script body, making these patterns reliably visible.

## Logic

```spl
`wineventlog_powershell_operational` EventID=4104
| where match(Message, "(?i)AmsiUtils|amsiInitFailed|amsi\.dll|System\.Management\.Automation\.AmsiUtils|VirtualProtect.*amsi")
| eval host_value = coalesce(Computer, host)
| stats count min(_time) as firstTime max(_time) as lastTime
        values(Message) as script_blocks
        by host_value
| rename host_value as dest
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

## Known false positives

- AMSI research / detection engineering work in PowerShell — yes, including this very repo's documentation if rendered to console. Allowlist by writer host or by a marker string in `lookups/allowlist_amsi_research.csv`
- Some defensive PowerShell modules legitimately reference AMSI APIs

## Tuning

- Combine with other signals: a 4104 match plus a corresponding T1059.001 process create from the same host in the last 5 minutes is a much higher-confidence finding
- Suppression: 1 hour per host

## Validation

- Atomic Red Team: T1562.001 #15 — AMSI bypass via SetValue
- Atomic Red Team: T1562.001 #28 — Patch AMSI bypass

Manual reproduction (note: this is a known signature, modern Defender will flag it):

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

## Response

See [`docs/runbooks/powershell-suspicious-execution.md`](../docs/runbooks/powershell-suspicious-execution.md).

AMSI bypass is a strong precursor signal. Treat as pre-attack staging.

1. Pull the host's other PowerShell activity in the same window
2. Check Defender state changes (T1562.001 detection) on the same host
3. Investigate any subsequent process creations (Sysmon EID 1) from `powershell.exe`/`pwsh.exe` on the host
