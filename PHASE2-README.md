# Detection content and Atomic Red Team validation

This document began as the Phase 2 delivery note. It now records the current
content state so that it does not compete with
[`coverage/coverage.md`](coverage/coverage.md), the promotion source of truth.

## Current inventory

- 18 detection specifications and 18 enabled saved-search stanzas.
- 7 Production detections backed by committed end-to-end evidence.
- 11 Testing candidates, including the Certutil rule whose validation exposed
  a renamed-binary gap.
- 19 distinct ATT&CK technique IDs across five tactics.
- 6 runbooks: five analyst-response guides and one ingestion guide.
- 8 CSV enrichment/tuning assets.
- Lookup definitions are deployed through
  `conf/splunk/local/transforms.conf`; `allowlist_lsass_access` matches the
  normalized executable name in `source_process_name`.
- Atomic test mapping is maintained in `tests/atomic/README.md`.

## Deploy the app content

Deploy configuration files into the matching directories of the
`splunk-detection-lab` app. Lookup CSV files belong in the app's `lookups`
directory; their definitions already live in `transforms.conf`.

```bash
APP=/opt/splunk/etc/apps/splunk-detection-lab

install -d "$APP/local" "$APP/lookups"
cp conf/splunk/local/*.conf "$APP/local/"
cp macros/macros.conf "$APP/local/macros.conf"
cp lookups/*.csv "$APP/lookups/"

sudo -u splunk /opt/splunk/bin/splunk btool check
sudo systemctl restart Splunkd
```

The dashboard XML, navigation, and static CSS must also be copied when
packaging the complete app. The command above intentionally focuses on the
content files discussed in this phase.

After restart, verify the saved-search inventory without placing credentials
in shell history:

```bash
sudo -u splunk /opt/splunk/bin/splunk list saved-search \
  -app splunk-detection-lab
```

## Install Atomic Red Team on the Windows lab endpoint

```powershell
.\scripts\install-atomic-redteam.ps1 -AddDefenderExclusion
```

The exclusion flag is lab-only. Never use it on a production workstation or on
a host that contains non-lab data.

## Validation and promotion workflow

For each Testing detection:

1. Take a VM snapshot.
2. Read the detection's exact validation procedure.
3. Run the mapped Atomic test or controlled manual reproduction.
4. Execute the candidate SPL over a tight time window.
5. Confirm the expected raw fields and the complete saved-search result.
6. Commit the Splunk result and relevant raw-event evidence.
7. Run the Atomic cleanup.
8. Document false positives and the implemented tuning control.
9. Promote the front matter, coverage table, and Navigator layer together.

A screenshot of test execution alone is not a successful detection
validation. Certutil intentionally remains Testing because its existing
evidence demonstrates a bypass and does not prove the revised
`OriginalFileName` path.

## Interview-ready, evidence-backed summary

- 18 detections are managed as code with hypotheses, source requirements, SPL,
  tuning, validation procedures, schedules, risk scores, and response paths.
- 7 are Production and 11 remain explicitly Testing.
- The knowledge layer is CIM-oriented; no accelerated CIM data model or full
  CIM compliance is claimed.
- Promotion failures are retained as engineering findings rather than relabeled
  as successes.
