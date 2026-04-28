---
id: <platform>_<datasource>_<attck>_<short-name>
title: <Human-readable title, ≤ 80 chars>
status: experimental            # experimental | testing | production | deprecated
author: <github-handle>
created: YYYY-MM-DD
modified: YYYY-MM-DD
severity: low                   # low | medium | high | critical
risk_score: 25                  # 0-100, used by RBA aggregation
attack:
  - tactic: defense-evasion
    technique: T1218.011
    sub_technique_name: Rundll32
data_source:
  index: sysmon
  sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  event_codes: [1]
  data_model: Endpoint.Processes
mitre_data_component: Process Creation
schedule:
  cron: "*/5 * * * *"
  earliest: "-10m@m"
  latest:   "-1m@m"
references:
  - https://attack.mitre.org/techniques/T1218/011/
  - https://lolbas-project.github.io/lolbas/Binaries/Rundll32/
tags:
  - lolbin
  - windows
---

## Hypothesis

> One paragraph. State the adversary behavior in plain English.
> Example: "Adversaries abuse `rundll32.exe` to proxy execution of malicious code through a signed Microsoft binary, bypassing application allowlists. Legitimate use of rundll32 is overwhelmingly initiated by `explorer.exe` or `services.exe` with a small, stable set of DLL targets; deviations from that baseline are suspicious."

## Logic

```spl
`sysmon_process_creation`
process_name="rundll32.exe"
| eval parent_name = mvindex(split(ParentImage,"\\"),-1)
| where NOT match(parent_name,"(?i)^(explorer|services|svchost|taskhost|wininit|userinit|sihost)\.exe$")
| eval suspicious_dll_inline = if(match(CommandLine,"(?i)javascript:|mshtml|shell32.*ShellExec_RunDLL|url\.dll.*FileProtocolHandler"),1,0)
| where suspicious_dll_inline=1 OR NOT match(CommandLine,"\.dll")
| `cim_endpoint_processes_rename`
| stats count min(_time) as firstTime max(_time) as lastTime
        values(CommandLine) as commandlines
        values(parent_process_name) as parent_process_names
        by dest user process_name process_guid
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

## Known false positives

- Microsoft Office repair routines occasionally invoke `rundll32` with no `.dll` argument from a non-explorer parent → allowlisted via `lookups/allowlist_rundll32.csv`
- Endpoint management agents (e.g., SCCM client `ccmexec.exe`) → enumerated in the parent allowlist above
- Localization helper `shell32.dll,Control_RunDLL` is benign when launched from `explorer.exe` — already excluded

## Tuning

- Lookup: `allowlist_rundll32.csv` keyed on `parent_process_name, command_pattern`
- Threshold: alert on every match. This is a low-volume rule after baseline tuning. If volume exceeds 5/day in your environment, the rule is mistuned, not the environment noisy.
- Suppression: 1 hour per `(dest, parent_process_name, hash_of_commandline)`

## Validation

- Atomic Red Team test: [T1218.011 #1 — `rundll32.exe javascript:`](../tests/atomic/T1218.011.md)
- Expected detection latency: < 5 minutes
- Evidence (screenshot + raw event): `tests/atomic/evidence/T1218.011-1.png`

Manual reproduction:

```powershell
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("calc.exe")
```

## Response

See [`docs/runbooks/lolbin-proxy-execution.md`](../docs/runbooks/lolbin-proxy-execution.md).

Quick triage checklist:

1. Confirm `rundll32` is unsigned or signed by an unexpected publisher (it should be Microsoft) — `Signed`, `Signature`, `SignatureStatus` from Sysmon EID 1
2. Pivot on `process_guid` for the full process tree (Sysmon EID 1 + 5 + 11)
3. Pivot on `dest` for outbound connections from `rundll32` in the same window (Sysmon EID 3)
4. Pull module loads (`dll_loaded`) for the same `process_guid` (Sysmon EID 7) — look for non-Microsoft signers
5. If the parent is a productivity app (Word, Outlook, browser): treat as suspected initial access, escalate to L3
6. Containment: isolate host via EDR/network ACL, capture memory if available
