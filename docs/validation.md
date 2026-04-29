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
index=sysmon EventID=1 earliest=-1h | head 1 | table _time host process_name CommandLine ParentImage User
```

Expected: a row with all fields populated. If `process_name` or `CommandLine` are empty, the field extractions in `splunk-app/default/props.conf` are not active. Check `btool props list` and reload.

## CIM mapping

```spl
index=sysmon eventtype=sysmon_process_create earliest=-1h | head 1
```

Expected: at least one event tagged `process` and `endpoint` from our `tags.conf`. If empty, the `eventtypes.conf` did not load.

## Clock skew

```spl
index=sysmon earliest=-1h
| eval delta = round((_indextime - _time), 0)
| stats avg(delta) as avg_skew_seconds by host
```

Expected: `avg_skew_seconds` close to zero. Significantly negative means the host clock is ahead of the indexer; see [`docs/runbooks/troubleshooting-ingestion.md`](runbooks/troubleshooting-ingestion.md).

## Saved searches

```bash
sudo -u splunk /opt/splunk/bin/splunk list saved-search -auth admin:PASSWORD -app splunk-detection-lab | grep "^name:" | wc -l
```

Expected: 18.