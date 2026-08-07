#!/usr/bin/env bash
set -euo pipefail

splunk_home="${SPLUNK_HOME:-/opt/splunk}"
splunk_bin="${splunk_home}/bin/splunk"

if [[ ! -x "${splunk_bin}" ]]; then
  echo "FAIL: Splunk CLI not found at the expected absolute path" >&2
  exit 1
fi

echo "## canary:auth"
"${splunk_bin}" btool props list 'canary:auth' --debug
echo "## canary_control_fields"
"${splunk_bin}" btool transforms list 'canary_control_fields' --debug
echo "## canary_auth_fields"
"${splunk_bin}" btool transforms list 'canary_auth_fields' --debug
