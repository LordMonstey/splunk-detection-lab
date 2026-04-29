# Troubleshooting - ingestion blind spots

## Clock skew between forwarder and indexer

**Symptom**: events appear in `index=sysmon` for `earliest=-24h` but not for `earliest=-1h`.

**Cause**: forwarder clock is ahead of the indexer, events are indexed with a future `_time` and fall outside relative-time windows.

**Diagnose**:

```spl
index=sysmon earliest=-24h
| eval delta = round((_indextime - _time), 0)
| stats avg(delta), max(delta) by host
```

Negative delta means the host clock is ahead.

**Fix**: enable NTP on both ends.
- Linux: `sudo timedatectl set-ntp true`
- Windows: `w32tm /resync /force`

## Field extraction returning empty

**Symptom**: events in `index=sysmon` but `EventCode`, `Image`, `User` are empty.

**Cause**: Splunk does not auto-parse `<EventData><Data Name='X'>` children of XmlWinEventLog without a Microsoft Windows TA. The lab does this manually via `EXTRACT-*` rules in `splunk-app/default/props.conf`.

**Fix**: add the regex extraction in `props.conf` and reload (`_reload` API or restart).
