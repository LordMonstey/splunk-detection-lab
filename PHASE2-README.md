# Phase 2 — 18 detections + Atomic Red Team validation framework

This drop adds:

- 18 detection files in `detections/` (all `status: testing`)
- 4 runbooks in `docs/runbooks/`
- 4 lookups in `lookups/` (allowlists for tuning)
- Updated `coverage/coverage.md` and `coverage/navigator-layer.json`
- All scheduled searches in `conf/splunk/local/savedsearches.conf`
- Atomic Red Team install script at `scripts/install-atomic-redteam.ps1`
- Atomic test mapping master at `tests/atomic/README.md`

## Overlay these files onto your repo

```powershell
cd "C:\Users\moi\Desktop\splunk-detection-lab.zip"
Expand-Archive -Path "$env:USERPROFILE\Downloads\phase2-overlay.zip" -DestinationPath . -Force
git status
git add .
git commit -m "feat(phase2): add 18 detections, 4 runbooks, atomic test mapping"
git push
```

## Deploy to your Splunk app on the Debian VM

The new `savedsearches.conf` and lookups need to land in `/opt/splunk/etc/apps/splunk-detection-lab/`.

```bash
cd /opt/splunk-lab/splunk-detection-lab
git pull

cp conf/splunk/local/savedsearches.conf splunk-app/local/savedsearches.conf
mkdir -p splunk-app/lookups
cp lookups/*.csv splunk-app/lookups/
cp lookups/lookups.conf splunk-app/default/transforms.conf 2>/dev/null || cp lookups/lookups.conf splunk-app/default/lookups.conf

sudo -u splunk /opt/splunk/bin/splunk btool check 2>&1 | grep -i splunk-detection-lab
sudo systemctl restart Splunkd
sleep 20
sudo -u splunk /opt/splunk/bin/splunk list saved-search -auth admin:PASSWORD | grep ^detect_ | head -20
```

You should see all 18 saved searches listed with prefix `detect_`.

## Install Atomic Red Team on the Windows VM

```powershell
.\scripts\install-atomic-redteam.ps1 -AddDefenderExclusion
```

The `-AddDefenderExclusion` flag is **lab-only**. It tells Defender not to scan `C:\AtomicRedTeam\`. Without it, Defender will quarantine half the test payloads. **Never use this flag on a production host.**

## Phase 3 — your turn

Per detection in `tests/atomic/README.md`:

1. Take a VM snapshot before starting (Atomic tests can leave artifacts)
2. Run the matching `Invoke-AtomicTest`
3. Verify the detection fires in Splunk Web
4. Screenshot + raw event into `tests/atomic/<technique>/evidence/`
5. Run cleanup: `Invoke-AtomicTest <id> -Cleanup`
6. Promote the detection to `status: production` in its `.md`
7. Update `coverage/coverage.md` to ✅ and the navigator score to 100
8. Commit per detection — small, reviewable, traceable

## What this gives you in interview

Concretely, you can now say:

- "I have 18 detections covering 17 ATT&CK techniques on Windows endpoint, all written as detection-as-code with hypothesis, FPs, tuning, validation, and runbook"
- "I built the CIM mapping for Sysmon by hand because I wanted to understand what the official TA does"
- "Each detection is validated via Atomic Red Team and the evidence is in the repo, pinned to a commit"
- "The MITRE coverage map is regenerated from the source-of-truth file and rendered in the ATT&CK Navigator"

That's not a lab anymore. That's a portfolio.
