# Runbook — Suspicious PowerShell execution

Applies to detections triggering on `powershell.exe`, `pwsh.exe`, or PowerShell script block logging (EID 4104). Covers encoded commands, download cradles, AMSI bypass, and high-entropy obfuscation.

**SLA**: triage within 30 minutes for medium severity, 10 minutes for high.

## 1. Validate the alert

Pull the full event:

```spl
`sysmon_process_creation` process_guid="<value-from-alert>"
| table _time host User Image CommandLine ParentImage ParentCommandLine Hashes Signed Signature
```

Checklist:

- [ ] Is `Image` the legitimate `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` or `C:\Program Files\PowerShell\7\pwsh.exe`?
- [ ] Is the binary signed by Microsoft? Unsigned PowerShell with this name is a hard escalation
- [ ] Decode the payload (Base64 → UTF-16LE for `-EncodedCommand`)
- [ ] Pull the script block from the PowerShell channel: `\`wineventlog_powershell_operational\` EventID=4104 host=<dest>`

## 2. Establish process tree

```spl
`sysmon_process_creation` (process_guid="<guid>" OR parent_process_guid="<guid>")
| sort _time
| table _time host User Image CommandLine
```

## 3. Network activity by the same process

```spl
`sysmon_network_connection` process_guid="<guid>"
| table _time host Image SourceIp SourcePort DestinationIp DestinationPort DestinationHostname
```

## 4. Containment

| Condition | Action |
|---|---|
| Parent is a productivity app (Word, Outlook, Acrobat, browser) | Initial access. Isolate, capture memory if available |
| Parent is wmiprvse / dcom from a non-admin context | Lateral movement. Check source host |
| Parent is a known IT script + admin context + change record | Likely benign, allowlist if confirmed |
| Cannot establish parent legitimacy within SLA | Escalate to L3 |

## 5. Closure

- Verdict and rationale in the ticket
- If FP: open a tuning PR against the relevant lookup, do not silently close
