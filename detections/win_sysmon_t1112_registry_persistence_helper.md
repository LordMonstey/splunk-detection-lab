---
id: win_sysmon_t1112_registry_persistence_helper
title: Registry write to known persistence keys (Image File Execution Options, AppInit, Winlogon)
status: testing
author: LordMonstey
created: 2026-04-28
modified: 2026-04-28
severity: high
risk_score: 70
attack:
  - tactic: persistence
    technique: T1546.012
    sub_technique_name: Image File Execution Options Injection
  - tactic: persistence
    technique: T1547.014
    sub_technique_name: Active Setup
  - tactic: defense-evasion
    technique: T1112
    sub_technique_name: Modify Registry
data_source:
  index: sysmon
  sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  event_codes: [13]
mitre_data_component: Windows Registry
schedule:
  cron: "*/10 * * * *"
  earliest: "-15m@m"
  latest:   "-1m@m"
references:
  - https://attack.mitre.org/techniques/T1546/012/
  - https://attack.mitre.org/techniques/T1547/014/
  - https://attack.mitre.org/techniques/T1112/
tags:
  - persistence
  - registry
---

## Hypothesis

A short list of registry keys are reliable persistence/hijack mechanisms: Image File Execution Options' `Debugger` value (T1546.012), `Winlogon\Userinit`/`Shell` (T1547.004), `AppInit_DLLs` (T1546.010), `ActiveSetup\Installed Components\*\StubPath` (T1547.014). Writes from anything other than `TrustedInstaller`/`msiexec` are anomalous.

## Logic

```spl
`sysmon_registry_event` EventID=13
( TargetObject="*\\Image File Execution Options\\*\\Debugger*"
   OR TargetObject="*\\Image File Execution Options\\*\\GlobalFlag*"
   OR TargetObject="*\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit*"
   OR TargetObject="*\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell*"
   OR TargetObject="*\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs*"
   OR TargetObject="*\\Active Setup\\Installed Components\\*\\StubPath*" )
| eval writer = mvindex(split(Image,"\\"), -1)
| where NOT match(writer, "(?i)^(TrustedInstaller|msiexec|setup|wuauclt|svchost)\.exe$")
| `cim_endpoint_processes_rename`
| stats count min(_time) as firstTime max(_time) as lastTime
        values(TargetObject) as registry_keys
        values(Details) as registry_values
        values(writer) as writers
        by dest user process_guid
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

## Known false positives

- Visual Studio installer touches IFEO during setup — allowlist by writer signature
- Some debugging tools add IFEO Debugger entries — typically from `windbg.exe` parents

## Tuning

- These keys see very low write traffic in production — rule should be near-zero noise after baseline
- Allowlist by `(writer, key_pattern)` in `lookups/allowlist_persistence_registry.csv`
- No aggressive suppression: each event matters

## Validation

- Atomic Red Team: T1546.012 #1 — IFEO Debugger
- Atomic Red Team: T1547.004 #1 — Winlogon Shell key

Manual reproduction (administrator required):

```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f
```

Cleanup:

```cmd
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /f
```

## Response

See [`docs/runbooks/persistence-investigation.md`](../docs/runbooks/persistence-investigation.md).

1. The Details field contains the persistence payload (typically a binary path or DLL) — resolve and hash
2. IFEO Debugger entries on common LOLBins (`sethc.exe`, `osk.exe`, `utilman.exe`) are sticky-keys backdoors — high-confidence finding
3. Pivot on writer → if a non-installer wrote here, treat as confirmed persistence
