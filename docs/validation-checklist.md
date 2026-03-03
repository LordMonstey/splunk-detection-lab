# Validation Checklist

## Objective

Confirm that:

- the Splunk server is reachable
- the Universal Forwarder is connected
- Windows Event Logs are indexed
- Sysmon Operational events are indexed
- basic detection searches work

## Debian Splunk Server Checks

```bash
/opt/splunk/bin/splunk status
ss -ltnp | egrep ':8000|:8089|:9997'
hostname -I
```

Expected:

- Splunkd is running
- TCP 8000 is listening
- TCP 8089 is listening
- TCP 9997 is listening

## Windows Forwarder Checks

```powershell
Get-Service SplunkForwarder
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" list forward-server -auth admin:ChangeThisPasswordNow_123!
```

Expected:

- service state is **Running**
- target forward server is **Active**

## Sysmon Source Checks

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 |
Select-Object TimeCreated, Id, ProviderName
```

Expected:

- recent Sysmon events are present

## Splunk Search Checks

### Telemetry summary

```spl
index=windows OR index=sysmon
| stats count by index, sourcetype
```

Expected:

- `windows` index contains native Windows sourcetypes
- `sysmon` index contains `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### Sysmon sourcetype validation

```spl
index=sysmon
| stats count by sourcetype
```

### Event code distribution

```spl
index=sysmon
| stats count by EventCode
| sort - count
```

### Process creation view

```spl
index=sysmon EventCode=1
| table _time host Image CommandLine ParentImage User
| sort - _time
```

### Network connection view

```spl
index=sysmon EventCode=3
| table _time host Image SourceIp SourcePort DestinationIp DestinationPort Protocol
| sort - _time
```

## Portfolio Screenshots to Capture

- Telemetry summary by index and sourcetype
- Sysmon sourcetype count
- Process creation query results
- Network connection query results
- Splunk Search home with successful query execution
