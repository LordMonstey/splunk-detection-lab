---
id: win_sysmon_t1562.001_defender_tamper
title: Windows Defender configuration tampering via registry or command
status: testing
author: LordMonstey
created: 2026-04-28
modified: 2026-04-28
severity: high
risk_score: 75
attack:
  - tactic: defense-evasion
    technique: T1562.001
    sub_technique_name: Disable or Modify Tools
data_source:
  index: sysmon
  sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  event_codes: [1, 13]
mitre_data_component: Process Creation, Windows Registry
schedule:
  cron: "*/5 * * * *"
  earliest: "-10m@m"
  latest:   "-1m@m"
references:
  - https://attack.mitre.org/techniques/T1562/001/
tags:
  - defense-evasion
  - defender
---

## Hypothesis

Adversaries disable Windows Defender real-time protection or add path/process exclusions before staging tooling. This detection covers two routes: PowerShell using `Set-MpPreference` / `Add-MpPreference`, and direct registry modifications under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`.

## Logic

```spl
(
   (`sysmon_process_creation` (process_name="powershell.exe" OR process_name="pwsh.exe")
    CommandLine="*MpPreference*"
    (CommandLine="*-DisableRealtimeMonitoring*" OR CommandLine="*-ExclusionPath*" OR CommandLine="*-ExclusionProcess*" OR CommandLine="*-ExclusionExtension*" OR CommandLine="*-DisableBehaviorMonitoring*" OR CommandLine="*-DisableScriptScanning*"))
OR
   (`sysmon_registry_event` EventID=13
    (TargetObject="*\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\*"
     OR TargetObject="*\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\*"
     OR TargetObject="*\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring*"))
)
| eval action_type = if(EventID==1, "powershell_cmd", "registry_write")
| `cim_endpoint_processes_rename`
| stats count min(_time) as firstTime max(_time) as lastTime
        values(CommandLine) as commandlines
        values(TargetObject) as registry_keys
        values(action_type) as actions
        by dest user process_guid
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

## Known false positives

- IT GPO deployment touches Defender policies legitimately — typically signed by `gpsvc` chain, allowlist via `lookups/allowlist_defender_writers.csv`
- Some development environment installers (Visual Studio, Docker Desktop) add their own Defender exclusions — must be allowlisted explicitly per product

## Tuning

- Allowlist by `(writer, target_pattern)` pair, not by writer alone
- Suppression: 24 hours per `(dest, action_type)`

## Validation

- Atomic Red Team: T1562.001 #16 — Disable Defender via PowerShell
- Atomic Red Team: T1562.001 #28 — Add Defender exclusion path

Manual reproduction (administrator required):

```powershell
Add-MpPreference -ExclusionPath "C:\AtomicTest\"
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```

Cleanup:

```powershell
Remove-MpPreference -ExclusionPath "C:\AtomicTest\"
```

## Response

See [`docs/runbooks/defense-evasion.md`](../docs/runbooks/defense-evasion.md).

1. Defender tampering is a near-certain precursor to malware execution. Treat as a high-confidence pre-attack signal.
2. Pivot on the user account that ran the command — verify legitimacy through change tickets
3. Search for binaries written to the excluded path in the same hour: `\`sysmon_file_create\` host=<dest> file_path=<excluded_path>*`
4. If the excluded path holds a non-trusted binary, escalate to IR
