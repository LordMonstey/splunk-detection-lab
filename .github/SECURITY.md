# Security policy

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability or an exposed
secret. Use the repository's
[private security advisory form](https://github.com/LordMonstey/splunk-detection-lab/security/advisories/new)
and include:

- the affected file, page, or commit;
- clear reproduction steps;
- the expected and observed behavior;
- the impact you believe is possible.

Reports are reviewed privately. A public disclosure or acknowledgement is made
only after the issue is contained and a fix is available.

## Supported version

Only the latest commit on `main` and the current GitHub Pages deployment are
supported. Historical lab snapshots are evidence artifacts, not running
services.

## Public-site boundary

The portfolio is a static GitHub Pages application. It has no backend, form
submission, live Splunk connection, analytics, cookies, or third-party script.
Published telemetry is aggregated and sanitized before it is committed.
