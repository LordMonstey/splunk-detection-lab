# Screenshot Guide

Add screenshots under the `screenshots/` directory and keep names clean and predictable.

## Suggested Files

- `01-index-summary.png`
- `02-sysmon-sourcetype.png`
- `03-sysmon-eventcode-breakdown.png`
- `04-process-creation.png`
- `05-network-connections.png`
- `06-splunk-search-overview.png`

## Recommended Captures

### 01-index-summary.png
Search:
```spl
index=windows OR index=sysmon
| stats count by index, sourcetype
```

### 02-sysmon-sourcetype.png
Search:
```spl
index=sysmon
| stats count by sourcetype
```

### 03-sysmon-eventcode-breakdown.png
Search:
```spl
index=sysmon
| stats count by EventCode
| sort - count
```

### 04-process-creation.png
Search:
```spl
index=sysmon EventCode=1
| table _time host Image CommandLine ParentImage User
| sort - _time
```

### 05-network-connections.png
Search:
```spl
index=sysmon EventCode=3
| table _time host Image SourceIp SourcePort DestinationIp DestinationPort Protocol
| sort - _time
```

### 06-splunk-search-overview.png
A clean wide screenshot showing:
- the search bar
- time range
- successful result count
- a useful table or statistics output

## Presentation Tips

- Use a consistent browser zoom level
- Avoid exposing passwords or personal details
- Keep the time range visible
- Capture only clean, readable result sets
- Use dark or light theme consistently across all screenshots
