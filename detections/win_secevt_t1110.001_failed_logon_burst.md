---
id: win_secevt_t1110.001_failed_logon_burst
title: Burst of failed logons (4625) against a single account or host
status: testing
author: LordMonstey
created: 2026-04-28
modified: 2026-04-28
severity: medium
risk_score: 50
attack:
  - tactic: credential-access
    technique: T1110.001
    sub_technique_name: Password Guessing
  - tactic: credential-access
    technique: T1110.003
    sub_technique_name: Password Spraying
data_source:
  index: windows
  sourcetype: XmlWinEventLog:Security
  event_codes: [4625]
mitre_data_component: Logon Session
schedule:
  cron: "*/5 * * * *"
  earliest: "-15m@m"
  latest:   "-1m@m"
references:
  - https://attack.mitre.org/techniques/T1110/001/
  - https://attack.mitre.org/techniques/T1110/003/
tags:
  - credential-access
  - brute-force
---

## Hypothesis

Brute-force and password-spray attacks emit clusters of `4625` (failed logon) events. Two patterns are interesting: many failures against one account (brute force), or many accounts each seeing one failure from the same source (spray). Both indicate authentication-layer probing.

## Logic

```spl
`wineventlog_security` EventID=4625
| bucket _time span=15m
| stats count
        dc(TargetUserName) as users_targeted
        values(TargetUserName) as users
        values(IpAddress) as src_ips
        values(LogonType) as logon_types
        by _time host
| where (count >= 10 AND users_targeted == 1)
     OR (users_targeted >= 5)
| eval pattern = case(users_targeted == 1, "brute_force_single_user",
                      users_targeted >= 5, "password_spray",
                      1==1, "other")
```

## Known false positives

- Misconfigured services with stale credentials (printer, mapped drive, scheduled task) — produce sustained 4625 noise from a single source IP
- Penetration testing windows — should be scheduled and excluded by IP allowlist
- Lockout policy retries from RDP brokers

## Tuning

- Add an exclusion list of service-account names that legitimately fail (rare but exists) in `lookups/allowlist_failed_logon.csv`
- Threshold of 10 per 15min for single user is conservative; tune to your environment after a week of baseline
- Suppression: 1 hour per `(host, src_ip)`

## Validation

- Atomic Red Team: T1110.001 #1 — RDP brute force (use cautiously, requires generating logon failures)

Manual reproduction (run from another box, against the lab):

```powershell
1..15 | ForEach-Object {
  $secpw = ConvertTo-SecureString "wrong-pass-$_" -AsPlainText -Force
  $cred = New-Object System.Management.Automation.PSCredential ('TEST VM', $secpw)
  Start-Process -Credential $cred -FilePath cmd.exe -ArgumentList '/c exit' -ErrorAction SilentlyContinue
}
```

## Response

See [`docs/runbooks/credential-access.md`](../docs/runbooks/credential-access.md).

1. Identify pattern — brute on a single user is targeted; spray means lateral-movement reconnaissance
2. Resolve `IpAddress` — internal vs external. Internal source means an insider host is compromised → escalate immediately
3. If external source → check whether the targeted account exists and is non-disabled; lock if necessary
4. Check for matching successful 4624 in the same window (the attack succeeded if so)
