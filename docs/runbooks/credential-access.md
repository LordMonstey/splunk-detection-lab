# Runbook — Credential access

Applies to detections on LSASS access (T1003.001), failed-logon bursts (T1110.001/003), and any future credential dumping signals. **Highest priority workflow** — credential theft preempts every other remediation, because rotated credentials must precede host cleanup.

**SLA**: 10 minutes for critical, 20 for medium. Credential access is never a queue item.

## 1. Containment first

Before investigating, isolate. Credential dumping has a runaway blast radius — every minute the host stays online is another minute the attacker can hop.

- Network isolation via EDR or firewall ACL
- Do **not** power off the host — memory artifacts are needed
- Capture memory if a tool is available

## 2. Forced credential rotation scope

Identify every account that authenticated to the host in the last 24 hours:

```spl
`wineventlog_security` (EventID=4624 OR EventID=4648) host=<dest>
earliest=-24h latest=now
| stats count by TargetUserName LogonType src_ip
```

Rotate, in this order of priority:

1. Privileged / admin accounts (especially LogonType 2/10 — interactive/RDP)
2. Service accounts that authenticated
3. Other accounts touched

For each rotated credential, also revoke any active sessions (`klist purge` is per-host; for AD, force re-auth via password change + Kerberos ticket invalidation).

## 3. What was accessed

Pull the dumping process's full activity:

```spl
`sysmon_process_creation` process_guid="<source_process_guid>"
| table _time host User Image CommandLine ParentImage Hashes
```

```spl
`sysmon_network_connection` process_guid="<source_process_guid>"
| table _time host DestinationIp DestinationPort DestinationHostname
```

```spl
`sysmon_file_create` process_guid="<source_process_guid>"
| table _time host TargetFilename
```

If a `lsass.dmp` (or any `.dmp`) was written: locate it, hash it, capture for IR. Adversaries often exfiltrate dumps for offline cracking.

## 4. Lateral propagation check

Credential theft is rarely solo. Search the wider environment for the same dumping process hash:

```spl
`sysmon_process_creation` Hashes="*<sha256>*"
| stats count by host User _time
```

If matched on >1 host → environment-wide credential incident.

## 5. Closure

This workflow does not close at the analyst level. Document findings, hand off to IR, do not mark resolved until forensic confirmation.
