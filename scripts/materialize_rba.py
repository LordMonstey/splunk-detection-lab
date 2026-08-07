#!/usr/bin/env python3
"""Materialize ES-compatible risk modifiers from validated saved searches.

This utility is intended for a controlled demonstration dataset.  It executes
selected installed detections, writes normalized risk events, and generates a
single multi-technique finding in the ``notable`` index.  ``finding_id`` and
``replay_id`` make repeated runs idempotent.  No raw event content or
credential is exported.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote

from validate_live_detections import SplunkClient, get_entries


RISK_SPECS = (
    {
        "search": "detect_win_sysmon_t1059_001_powershell_encoded",
        "detection_id": "win_sysmon_t1059.001_powershell_encoded",
        "technique": "T1059.001",
        "story": "Suspicious PowerShell Execution",
        "severity": "high",
        "risk_score": 60,
        "message": "Encoded PowerShell execution observed on a Windows endpoint",
    },
    {
        "search": "detect_win_sysmon_t1003_001_lsass_access_suspicious",
        "detection_id": "win_sysmon_t1003.001_lsass_access_suspicious",
        "technique": "T1003.001",
        "story": "Credential Access",
        "severity": "critical",
        "risk_score": 90,
        "message": "Suspicious process access to LSASS observed on a Windows endpoint",
    },
    {
        "search": "detect_win_sysmon_t1140_certutil_decode",
        "detection_id": "win_sysmon_t1140_certutil_decode",
        "technique": "T1140",
        "story": "Signed Binary Proxy and Decode Activity",
        "severity": "medium",
        "risk_score": 60,
        "message": "Certutil decode or transfer behavior observed on a Windows endpoint",
    },
    {
        "search": "detect_win_secevt_t1136_001_local_account_creation",
        "detection_id": "win_secevt_t1136.001_local_account_creation",
        "technique": "T1136.001",
        "story": "Account Persistence",
        "severity": "medium",
        "risk_score": 55,
        "message": "Local account creation observed on a Windows endpoint",
    },
    {
        "search": "detect_win_sysmon_t1547_001_run_key_modification",
        "detection_id": "win_sysmon_t1547.001_run_key_modification",
        "technique": "T1547.001",
        "story": "Registry Run Key Persistence",
        "severity": "medium",
        "risk_score": 55,
        "message": "Registry Run or RunOnce persistence observed on a Windows endpoint",
    },
)


def spl_quote(value: str) -> str:
    """Return a quoted SPL string literal for trusted script metadata."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def oneshot(client: SplunkClient, search: str) -> dict[str, Any]:
    return client.request(
        "/services/search/jobs",
        method="POST",
        params={
            "search": search,
            "exec_mode": "oneshot",
            "earliest_time": "0",
            "latest_time": "now",
            "output_mode": "json",
        },
    )


def saved_search_query(client: SplunkClient, app: str, name: str) -> str:
    path = (
        f"/servicesNS/nobody/{quote(app, safe='')}/saved/searches/"
        f"{quote(name, safe='')}"
    )
    entries = get_entries(client.request(path))
    if not entries:
        raise ValueError(f"Saved search not found: {name}")
    query = str(entries[0].get("content", {}).get("search", "")).strip()
    if not query:
        raise ValueError(f"Saved search is empty: {name}")
    return query


def materialize_risk(
    client: SplunkClient,
    app: str,
    replay_id: str,
) -> list[dict[str, Any]]:
    outcomes: list[dict[str, Any]] = []
    for spec in RISK_SPECS:
        query = saved_search_query(client, app, spec["search"])
        detection_id = spl_quote(spec["detection_id"])
        risk_message = spl_quote(spec["message"])
        replay = spl_quote(replay_id)
        spl = (
            f"search {query} "
            f"| eval _time=now(), detection_id={detection_id}, "
            f"mitre_technique={spl_quote(spec['technique'])}, "
            f"analytic_story={spl_quote(spec['story'])}, "
            f"severity={spl_quote(spec['severity'])}, "
            f"risk_score={int(spec['risk_score'])}, risk_object=coalesce(dest,host,\"unknown\"), "
            f"risk_object_type=\"system\", risk_message={risk_message}, "
            f"search_name={spl_quote(spec['search'])}, replay_id={replay}, "
            "evidence_key=coalesce(process_guid,SourceProcessGUID,mvjoin(commandlines,\";\"),"
            "mvjoin(run_keys,\";\"),mvjoin(new_account,\";\"),tostring(firstTime),\"aggregate\"), "
            "finding_id=sha256(detection_id.\"|\".risk_object.\"|\".evidence_key.\"|\".replay_id) "
            f"| search NOT [ search index=risk replay_id={replay} "
            "| fields finding_id | format ] "
            "| fields _time risk_object risk_object_type risk_score risk_message search_name "
            "detection_id mitre_technique analytic_story severity finding_id replay_id dest user "
            "firstTime lastTime count "
            "| collect index=risk source=\"splunk-detection-lab:rba\" sourcetype=\"stash\""
        )
        payload = oneshot(client, spl)
        fatal = [
            message
            for message in payload.get("messages", [])
            if str(message.get("type", "")).upper() in {"FATAL", "ERROR"}
        ]
        outcomes.append(
            {
                "search": spec["search"],
                "detection_id": spec["detection_id"],
                "risk_score": spec["risk_score"],
                "status": "failed" if fatal else "completed",
                "messages": [
                    {"type": item.get("type"), "text": str(item.get("text", ""))[:300]}
                    for item in fatal
                ],
            }
        )
    return outcomes


def materialize_finding(client: SplunkClient, replay_id: str) -> dict[str, Any]:
    replay = spl_quote(replay_id)
    title = "RBA - Multi-technique Windows attack chain"
    spl = (
        f"search index=risk replay_id={replay} earliest=0 "
        "| stats sum(risk_score) as risk_score dc(mitre_technique) as technique_count "
        "values(mitre_technique) as mitre_techniques values(detection_id) as detections "
        "values(analytic_story) as analytic_stories min(_time) as firstTime max(_time) as lastTime "
        "count as risk_modifier_count by risk_object risk_object_type "
        "| where risk_score>=150 AND technique_count>=2 "
        f"| eval _time=now(), rule_title={spl_quote(title)}, rule_name=rule_title, "
        "severity=case(risk_score>=500,\"critical\",risk_score>=250,\"high\",1=1,\"medium\"), "
        "status=\"new\", owner=\"unassigned\", "
        "description=\"Multiple independent Windows detections raised cumulative risk for the same entity\", "
        f"replay_id={replay}, finding_key=sha256(rule_title.\"|\".risk_object.\"|\".replay_id), "
        "finding_id=sha256(finding_key.\"|\".tostring(risk_score).\"|\".tostring(technique_count)) "
        f"| search NOT [ search index=notable replay_id={replay} | fields finding_id | format ] "
        "| fields _time rule_title rule_name severity status owner description risk_score "
        "risk_object risk_object_type technique_count mitre_techniques detections analytic_stories "
        "firstTime lastTime risk_modifier_count replay_id finding_key finding_id "
        "| collect index=notable source=\"splunk-detection-lab:rba\" sourcetype=\"stash\""
    )
    payload = oneshot(client, spl)
    fatal = [
        message
        for message in payload.get("messages", [])
        if str(message.get("type", "")).upper() in {"FATAL", "ERROR"}
    ]
    return {
        "status": "failed" if fatal else "completed",
        "messages": [
            {"type": item.get("type"), "text": str(item.get("text", ""))[:300]}
            for item in fatal
        ],
    }


def measure(client: SplunkClient, replay_id: str) -> dict[str, Any]:
    replay = spl_quote(replay_id)
    risk = oneshot(
        client,
        f"search index=risk replay_id={replay} earliest=0 "
        "| stats count as modifiers sum(risk_score) as cumulative_risk "
        "dc(detection_id) as detections dc(mitre_technique) as techniques "
        "dc(risk_object) as entities",
    )
    notable = oneshot(
        client,
        f"search index=notable replay_id={replay} earliest=0 "
        "| stats latest(risk_score) as current_risk dc(finding_id) as versions "
        "by risk_object rule_title "
        "| stats count as findings max(current_risk) as highest_risk sum(versions) as versions",
    )
    return {
        "risk": (risk.get("results") or [{}])[0],
        "notable": (notable.get("results") or [{}])[0],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uri", required=True)
    parser.add_argument("--username", default="admin")
    parser.add_argument("--app", default="splunk-detection-lab")
    parser.add_argument("--replay-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    password = os.environ.pop("SPLUNK_PASSWORD", "")
    if not password:
        password = getpass.getpass(f"Splunk password for {args.username}: ")
    try:
        client = SplunkClient(args.uri, args.username, password)
        risk_outcomes = materialize_risk(client, args.app, args.replay_id)
        metrics = measure(client, args.replay_id)
        for _ in range(20):
            visible_detections = int(metrics["risk"].get("detections", 0) or 0)
            if visible_detections >= len(RISK_SPECS):
                break
            time.sleep(0.5)
            metrics = measure(client, args.replay_id)
        finding_outcome = materialize_finding(client, args.replay_id)
        for _ in range(20):
            metrics = measure(client, args.replay_id)
            visible_risk = int(metrics["risk"].get("cumulative_risk", 0) or 0)
            finding_risk = int(metrics["notable"].get("highest_risk", 0) or 0)
            if (
                int(metrics["notable"].get("findings", 0) or 0) >= 1
                and finding_risk >= visible_risk
            ):
                break
            time.sleep(0.5)
    except (HTTPError, URLError, TimeoutError, ValueError, IndexError) as error:
        print(f"ERROR: RBA materialization failed: {error}", file=sys.stderr)
        return 1
    finally:
        password = ""

    report = {
        "schema_version": 1,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "replay_id": args.replay_id,
        "risk_actions": risk_outcomes,
        "finding_action": finding_outcome,
        "metrics": metrics,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    failed = sum(item["status"] != "completed" for item in risk_outcomes)
    failed += finding_outcome["status"] != "completed"
    print(
        f"OK: risk={metrics['risk']} notable={metrics['notable']} "
        f"failures={failed}; report={args.output}"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
