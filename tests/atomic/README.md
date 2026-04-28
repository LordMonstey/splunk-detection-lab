# Atomic Red Team — Validation Suite

This folder maps every detection in `detections/` to one or more Atomic Red Team tests, and stores the evidence (screenshot + raw event) that proves the detection fired.

## Directory layout

```
tests/atomic/
├── README.md                 # this file
├── T1218.011.md              # mapping notes per technique
├── T1059.001.md
├── T1547.001.md
└── evidence/
    ├── T1218.011-1.png       # Splunk search result screenshot
    ├── T1218.011-1.raw.json  # the raw event(s) that triggered
    └── ...
```

## Workflow

For every detection moving from `testing` → `production`:

1. Identify the matching Atomic test ID(s) from <https://github.com/redcanaryco/atomic-red-team>
2. On the Windows VM, run the test via Invoke-AtomicRedTeam:
   ```powershell
   Invoke-AtomicTest T1218.011 -TestNumbers 1 -GetPrereqs
   Invoke-AtomicTest T1218.011 -TestNumbers 1
   ```
3. In Splunk, run the detection's SPL with a tight time window covering the test execution
4. Capture the result screenshot to `evidence/<technique>-<test#>.png`
5. Export the raw triggering event(s) to `evidence/<technique>-<test#>.raw.json`
6. Update the technique's mapping file (`<technique>.md`) with date, test ID, latency, and evidence link
7. Update `coverage/coverage.md` status to `production`
8. Update `coverage/navigator-layer.json` score to 100 for the technique

## Cleanup

Always run cleanup after a test:

```powershell
Invoke-AtomicTest T1218.011 -TestNumbers 1 -Cleanup
```

Tests that leave artifacts in `evidence/raw/` (memory captures, dropped binaries) are gitignored — only curated screenshots and JSON exports are committed.
