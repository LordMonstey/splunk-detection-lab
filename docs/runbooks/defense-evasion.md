# Runbook — Defense evasion

Applies to detections on Defender tampering (T1562.001), permission relaxation (T1222.001), and similar control-weakening behaviors.

**Important framing**: defense evasion is rarely the goal — it is the *prelude*. A confirmed evasion event means another action is imminent (or has just occurred). Treat as a leading indicator.

## 1. Identify the weakening

What was changed:

- Defender exclusion: which path / process / extension?
- Defender state: real-time monitoring off? Behavior monitoring off?
- ACL change: which path was opened, to which principal?

The relevant fields:

- `CommandLine` for PowerShell-driven changes (Set-MpPreference / Add-MpPreference)
- `TargetObject` + `Details` for registry-driven changes
- `CommandLine` for icacls

## 2. What the weakening enables

Look for activity in the affected scope **immediately after** the change:

For a Defender exclusion path:

```spl
`sysmon_file_create` host=<dest> file_path="<excluded_path>*" earliest=<change_time>
```

For a relaxed ACL on a directory:

```spl
`sysmon_file_create` host=<dest> file_path="<directory>*" earliest=<change_time>
```

## 3. Decision tree

| Finding | Action |
|---|---|
| Change was made by IT under change ticket | Confirm ticket, allowlist if recurring, close as benign |
| Change was made by user account on user's own host | Suspicious if user is non-admin; verify account legitimacy |
| Change preceded malware execution in same window | Confirmed pre-attack staging — escalate, isolate host |
| Cannot establish legitimacy | Escalate to L3 |

## 4. Always reverse the change

Whether benign or malicious, weakened controls do not stay weakened. After investigation, revert:

- Remove Defender exclusions: `Remove-MpPreference -ExclusionPath <p>`
- Restore Defender state: `Set-MpPreference -DisableRealtimeMonitoring $false`
- Reset ACLs: `icacls <path> /reset /T /C`

Document the reversal in the ticket.
