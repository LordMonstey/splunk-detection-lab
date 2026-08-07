#!/usr/bin/env python3
"""Network-free tests for the periodic-reporting live qualification gate."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import qualify_periodic_reporting_live as live  # noqa: E402


EXPECTED_ACL = {
    "app": live.APP_ID,
    "owner": "nobody",
    "sharing": "global",
    "perms": {"read": ["*"], "write": ["admin"]},
}


def feed(
    content: dict[str, Any],
    name: str = "entry",
    acl: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {"entry": [{"name": name, "content": content, "acl": acl or EXPECTED_ACL}]}


def aggregate(row_count: int, *, invalid_rows: int = 0, duplicate_keys: int = 0) -> dict[str, str]:
    populated = row_count > 0
    return {
        "row_count": str(row_count),
        "valid_rows": str(max(0, row_count - invalid_rows)),
        "invalid_rows": str(invalid_rows),
        "duplicate_keys": str(duplicate_keys),
        "family_count": "2" if populated else "0",
        "mco_daily_periods": "1" if populated else "0",
        "cim_weekly_periods": "1" if populated else "0",
    }


class FakeClient:
    def __init__(
        self,
        *,
        disabled: bool = False,
        acl: dict[str, Any] | None = None,
        replay_rows: int = 16,
    ) -> None:
        self.disabled = disabled
        self.acl = acl or EXPECTED_ACL
        self.replay_rows = replay_rows
        self.posts: list[str] = []
        self.deletes: list[str] = []
        self.job_reads = 0
        self.aggregate_reads = 0

    def get(self, path: str, **_params: Any) -> dict[str, Any]:
        if path == "/services/server/info":
            return feed({"version": "10.2.1", "kvStoreStatus": "ready"}, acl=self.acl)
        if path == "/services/server/health/splunkd":
            return feed({"health": "green"}, acl=self.acl)
        if path == f"/services/apps/local/{live.APP_ID}":
            return feed(
                {"version": "0.7.3", "disabled": False, "configured": True},
                acl=self.acl,
            )
        if "/storage/collections/config/" in path:
            content = {"enforceTypes": True}
            content.update(
                {f"field.{field}": kind for field, kind in live.KV_FIELD_CONTRACT.items()}
            )
            return feed(content, live.COLLECTION_NAME, self.acl)
        if "/configs/conf-transforms/" in path:
            return feed(
                {
                    "external_type": "kvstore",
                    "collection": live.COLLECTION_NAME,
                    "fields_list": ", ".join(["_key", *live.KV_FIELD_CONTRACT]),
                },
                live.LOOKUP_NAME,
                self.acl,
            )
        if "/data/ui/views/periodic_mco_cim_reporting" in path:
            return feed(
                {
                    "eai:data": (
                        '<dashboard version="1.1"><label>Reporting</label><row><panel><table>'
                        '<search><query>| inputlookup mco_cim_periodic_history | stats count'
                        '</query></search></table></panel></row></dashboard>'
                    )
                },
                "periodic_mco_cim_reporting",
                self.acl,
            )
        if "/saved/searches/" in path:
            name = next(value for value in live.SAVED_SEARCHES if value in path)
            expected = live.SEARCH_CONTRACT[name]
            return feed(
                {
                    "disabled": self.disabled,
                    "is_scheduled": True,
                    "next_scheduled_time": "2030-01-01T01:15:00+00:00",
                    **expected,
                    "search": (
                        "| makeresults | eval _key=sha256(report_key) "
                        "| fields _key schema_version report_key report_family period_start "
                        "period_end generated_at metric_id metric_value metric_unit status "
                        "sample_state threshold_profile "
                        "| outputlookup append=true key_field=_key mco_cim_periodic_history"
                    ),
                },
                name,
                self.acl,
            )
        if path.startswith("/services/search/jobs/"):
            self.job_reads += 1
            return feed(
                {
                    "isDone": True,
                    "isFailed": False,
                    "dispatchState": "DONE",
                    "runDuration": 0.25,
                    "resultCount": 7 if self.job_reads % 2 else 9,
                    "messages": [],
                },
                acl=self.acl,
            )
        raise AssertionError(f"unexpected GET path: {path}")

    def post(self, path: str, _data: dict[str, Any]) -> dict[str, Any]:
        self.posts.append(path)
        return {"sid": f"private-sid-{len(self.posts)}"}

    def delete(self, path: str) -> None:
        self.deletes.append(path)

    def run_search_job(self, search: str, **_params: Any) -> dict[str, Any]:
        self.validation_search = search
        self.aggregate_reads += 1
        if self.aggregate_reads == 1:
            row = aggregate(0)
        elif self.aggregate_reads == 2:
            row = aggregate(16)
        else:
            row = aggregate(self.replay_rows)
        return {"sid": "private-validation-sid", "results": [row]}


class PeriodicReportingLiveQualificationTests(unittest.TestCase):
    def qualify(self, client: FakeClient) -> dict[str, Any]:
        return live.qualify(
            client,
            live.APP_ID,
            timeout_seconds=5,
            expected_app_version="0.7.3",
            tls_verified=True,
        )

    def test_first_execution_and_idempotence_pass_without_claiming_trend(self) -> None:
        client = FakeClient()
        evidence = self.qualify(client)
        self.assertEqual(evidence["status"], "PASS")
        self.assertEqual(len(evidence["dispatches"]), 4)
        self.assertEqual(len(client.posts), 4)
        self.assertEqual(len(client.deletes), 4)
        self.assertTrue(
            evidence["aggregate_execution"]["first_execution_from_empty_collection"]
        )
        self.assertTrue(evidence["aggregate_execution"]["keyed_replay_stable"])
        self.assertFalse(evidence["trend_eligible"])
        self.assertFalse(evidence["trend_claimed"])
        self.assertTrue(all(evidence["checks"].values()))

    def test_runtime_contract_covers_scheduler_acl_and_dashboard(self) -> None:
        evidence = self.qualify(FakeClient())
        contract = evidence["runtime_contract"]
        self.assertTrue(contract["all_passed"])
        self.assertEqual(contract["acl"]["objects_checked"], 5)
        self.assertTrue(contract["acl"]["policy_passed"])
        self.assertTrue(contract["dashboard"]["aggregate_only"])
        self.assertTrue(all(item["next_run_present"] for item in contract["collectors"]))

    def test_public_evidence_excludes_private_runtime_details(self) -> None:
        evidence = self.qualify(FakeClient())
        canonical = json.dumps(evidence, sort_keys=True)
        self.assertNotIn("private-sid", canonical)
        self.assertNotIn("https://", canonical)
        self.assertNotRegex(canonical, r"192\.168\.|Authorization|Basic ")
        self.assertFalse(evidence["security"]["metric_values_included"])

    def test_disabled_collector_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "preflight contract failed"):
            self.qualify(FakeClient(disabled=True))

    def test_acl_drift_fails_before_dispatch(self) -> None:
        weak_acl = {
            **EXPECTED_ACL,
            "perms": {"read": ["*"], "write": ["admin", "power"]},
        }
        client = FakeClient(acl=weak_acl)
        with self.assertRaisesRegex(ValueError, "preflight contract failed"):
            self.qualify(client)
        self.assertEqual(client.posts, [])

    def test_non_idempotent_replay_fails_the_gate(self) -> None:
        evidence = self.qualify(FakeClient(replay_rows=32))
        self.assertEqual(evidence["status"], "FAIL")
        self.assertFalse(evidence["checks"]["keyed_replay_is_idempotent"])

    def test_validation_search_reads_only_the_aggregate(self) -> None:
        client = FakeClient()
        live.aggregate_validation(client)
        self.assertTrue(client.validation_search.startswith("| inputlookup "))
        self.assertNotIn("index=", client.validation_search)
        self.assertNotIn("_raw", client.validation_search)

    def test_version_like_platform_value_is_not_treated_as_private_ip(self) -> None:
        self.assertIsNone(live.PRIVATE_MARKER.search('"version": "10.2.1"'))
        self.assertIsNotNone(live.PRIVATE_MARKER.search('"host": "10.2.1.7"'))

    def test_published_live_evidence_is_sanitized_and_baseline_only(self) -> None:
        path = (
            ROOT
            / "artifacts"
            / "public"
            / "periodic-reporting-live-evidence-10.2.1-20260807.json"
        )
        evidence = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(evidence["schema_version"], 2)
        self.assertEqual(evidence["status"], "PASS")
        self.assertTrue(all(evidence["checks"].values()))
        self.assertTrue(
            evidence["aggregate_execution"]["first_execution_from_empty_collection"]
        )
        self.assertTrue(evidence["aggregate_execution"]["keyed_replay_stable"])
        replay = evidence["aggregate_execution"]["after_idempotence_replay"]
        self.assertEqual(replay["row_count"], 16)
        self.assertEqual(replay["invalid_rows"], 0)
        self.assertEqual(replay["duplicate_keys"], 0)
        self.assertEqual(
            evidence["historical_periods_observed"],
            {"mco_daily": 1, "cim_weekly": 1},
        )
        self.assertFalse(evidence["trend_eligible"])
        self.assertFalse(evidence["trend_claimed"])
        self.assertIsNone(
            live.PRIVATE_MARKER.search(json.dumps(evidence, sort_keys=True))
        )


if __name__ == "__main__":
    unittest.main()
