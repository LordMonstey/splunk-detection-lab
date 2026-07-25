# Validation

After the lab is built, run these checks to confirm telemetry is reaching Splunk and being normalized correctly.

## Ingestion

```spl
index=sysmon earliest=-15m | stats count by sourcetype, host
```

Expected: at least one row with sourcetype `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` and host equal to your Windows endpoint.

```spl
index=windows earliest=-15m | stats count by sourcetype
```

Expected: rows for `XmlWinEventLog:Security`, `XmlWinEventLog:System`, `XmlWinEventLog:Application`, `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational`.

## Field extraction

```spl
`sysmon_process_creation`
| `cim_endpoint_processes_rename`
| head 1
| table _time dest user process_name process parent_process CommandLine
```

Expected: a row with the raw Sysmon fields plus the CIM-oriented aliases
emitted by the macro. If `CommandLine` is empty, verify XML field extraction
with `btool props list`. If aliases are empty, verify the macro definition with
`btool macros list`.

## CIM-oriented normalization

```spl
`sysmon_process_creation`
| `cim_endpoint_processes_rename`
| head 1
| table dest user process process_name parent_process process_guid
```

Expected: the macro returns stable endpoint-oriented field names. This app does
not ship `eventtypes.conf`, `tags.conf`, or an accelerated Endpoint data model;
the check proves macro normalization, not full CIM compliance.

## Clock skew

```spl
index=sysmon earliest=-1h
| eval delta = round((_indextime - _time), 0)
| stats avg(delta) as avg_skew_seconds by host
```

Expected: `avg_skew_seconds` close to zero. Significantly negative means the host clock is ahead of the indexer; see [`docs/runbooks/troubleshooting-ingestion.md`](runbooks/troubleshooting-ingestion.md).

## Saved searches

```bash
sudo -u splunk /opt/splunk/bin/splunk list saved-search \
  -app splunk-detection-lab | grep "^name:" | wc -l
```

Expected: 18.
