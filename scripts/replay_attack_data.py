#!/usr/bin/env python3
"""Replay a compact, reproducible Splunk Attack Data campaign through HEC.

Only official public datasets are downloaded.  The HEC token is read from the
environment and is never printed or persisted by this script.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import ssl
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "tmp" / "attack_data"


@dataclass(frozen=True)
class Scenario:
    name: str
    technique: str
    url: str
    cache_name: str
    index: str
    sourcetype: str
    source: str
    pattern: re.Pattern[str]
    limit: int


SYSMON_URLS = {
    "powershell": "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1027/atomic_red_team/windows-sysmon.log",
    "lsass": "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log",
    "run_key": "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.001/atomic_red_team/windows-sysmon.log",
    "certutil": "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1140/atomic_red_team/windows-sysmon.log",
}


SCENARIOS = (
    Scenario(
        "encoded_powershell",
        "T1059.001",
        SYSMON_URLS["powershell"],
        "powershell_encoded.log",
        "sysmon",
        "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        re.compile(
            r"<EventID>1</EventID>.*<Data Name='Image'>[^<]*powershell\.exe</Data>.*"
            r"<Data Name='CommandLine'>[^<]*(?:EncodedCommand|\s-enc(?:odedcommand)?\s)",
            re.IGNORECASE,
        ),
        12,
    ),
    Scenario(
        "registry_run_key",
        "T1547.001",
        SYSMON_URLS["run_key"],
        "run_key.log",
        "sysmon",
        "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        re.compile(
            r"<EventID>13</EventID>.*<Data Name='TargetObject'>[^<]*"
            r"\\CurrentVersion\\Run(?:Once)?\\",
            re.IGNORECASE,
        ),
        12,
    ),
    Scenario(
        "lsass_memory_access",
        "T1003.001",
        SYSMON_URLS["lsass"],
        "lsass_access.log",
        "sysmon",
        "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        re.compile(
            r"<EventID>10</EventID>.*<Data Name='TargetImage'>[^<]*\\lsass\.exe</Data>.*"
            r"<Data Name='GrantedAccess'>0x(?:1010|1410|1438|143a|1fffff)</Data>",
            re.IGNORECASE,
        ),
        12,
    ),
    Scenario(
        "certutil_decode",
        "T1140",
        SYSMON_URLS["certutil"],
        "certutil_decode.log",
        "sysmon",
        "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        re.compile(
            r"<EventID>1</EventID>.*<Data Name='Image'>[^<]*\\certutil\.exe</Data>.*"
            r"<Data Name='CommandLine'>[^<]*\s-(?:decode|decodehex|urlcache)\b",
            re.IGNORECASE,
        ),
        12,
    ),
    Scenario(
        "local_account_creation",
        "T1136.001",
        "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/windows-security.log",
        "local_account_security.log",
        "windows",
        "XmlWinEventLog:Security",
        "WinEventLog:Security",
        re.compile(r"<EventID>4720</EventID>", re.IGNORECASE),
        12,
    ),
)


BASELINE = Scenario(
    "process_baseline",
    "BASELINE",
    SYSMON_URLS["powershell"],
    "powershell_encoded.log",
    "sysmon",
    "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    re.compile(r"<EventID>1</EventID>", re.IGNORECASE),
    160,
)


def download(scenario: Scenario) -> Path:
    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / scenario.cache_name
    if path.is_file() and path.stat().st_size > 0:
        return path
    request = Request(scenario.url, headers={"User-Agent": "splunk-detection-lab-replay/1.0"})
    with urlopen(request, timeout=90) as response:
        payload = response.read()
    path.write_bytes(payload)
    return path


def select_events(scenario: Scenario) -> list[str]:
    if scenario.name == "local_account_creation":
        text = download(scenario).read_text(encoding="utf-8", errors="replace")
        blocks = re.split(r"(?=^\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}\s+[AP]M\s*$)", text, flags=re.MULTILINE)
        converted = [plain_security_to_xml(block) for block in blocks if "EventCode=4720" in block]
        selected = [event for event in converted if event][: scenario.limit]
        if not selected:
            raise RuntimeError(f"No matching event found for scenario {scenario.name}")
        return selected

    selected: list[str] = []
    with download(scenario).open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            event = line.strip()
            if not event or not scenario.pattern.search(event):
                continue
            selected.append(event)
            if len(selected) >= scenario.limit:
                break
    if not selected:
        raise RuntimeError(f"No matching event found for scenario {scenario.name}")
    return selected


def plain_security_to_xml(block: str) -> str:
    """Convert one official WinEventLog text event to the XML shape used by the lab."""
    computer_match = re.search(r"^ComputerName=(.+)$", block, re.MULTILINE)
    event_match = re.search(r"^EventCode=(\d+)$", block, re.MULTILINE)
    account_matches = re.findall(r"^\s*Account Name:\s*(.+)$", block, re.MULTILINE)
    domain_matches = re.findall(r"^\s*Account Domain:\s*(.+)$", block, re.MULTILINE)
    if not event_match:
        return ""
    computer = computer_match.group(1).strip() if computer_match else "WIN10-LAB01"
    subject = account_matches[0].strip() if account_matches else "unknown"
    target = account_matches[1].strip() if len(account_matches) > 1 else "new-user"
    domain = domain_matches[1].strip() if len(domain_matches) > 1 else "LAB"
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System><Provider Name='Microsoft-Windows-Security-Auditing'/>"
        f"<EventID>{html.escape(event_match.group(1))}</EventID>"
        f"<Computer>{html.escape(computer)}</Computer></System><EventData>"
        f"<Data Name='TargetUserName'>{html.escape(target)}</Data>"
        f"<Data Name='TargetDomainName'>{html.escape(domain)}</Data>"
        f"<Data Name='SubjectUserName'>{html.escape(subject)}</Data>"
        "</EventData></Event>"
    )


def send_batch(uri: str, token: str, documents: list[dict]) -> None:
    body = "\n".join(json.dumps(item, ensure_ascii=False) for item in documents).encode("utf-8")
    request = Request(
        f"{uri.rstrip('/')}/services/collector/event",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "splunk-detection-lab-replay/1.0",
        },
    )
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with urlopen(request, timeout=30, context=context) as response:
        result = json.loads(response.read().decode("utf-8"))
    if result.get("code") != 0:
        raise RuntimeError(f"HEC rejected replay batch: code={result.get('code')}")


def replay(uri: str, token: str, output: Path, replay_id: str) -> dict:
    campaign: list[tuple[Scenario, str]] = []
    positive_fingerprints: set[str] = set()
    scenario_counts: dict[str, int] = {}

    for scenario in SCENARIOS:
        events = select_events(scenario)
        scenario_counts[scenario.name] = len(events)
        for event in events:
            campaign.append((scenario, event))
            positive_fingerprints.add(event)

    baseline_events = [
        event for event in select_events(BASELINE)
        if event not in positive_fingerprints
    ][:120]
    scenario_counts[BASELINE.name] = len(baseline_events)
    campaign.extend((BASELINE, event) for event in baseline_events)

    now = time.time()
    documents: list[dict] = []
    sent = 0
    for position, (scenario, event) in enumerate(campaign):
        documents.append(
            {
                "time": now - (len(campaign) - position) * 3,
                "host": "WIN10-LAB01",
                "index": scenario.index,
                "source": f"splunk_attack_data:{scenario.name}:{replay_id}",
                "sourcetype": scenario.sourcetype,
                "event": event,
            }
        )
        if sum(len(item["event"]) for item in documents) >= 350_000:
            send_batch(uri, token, documents)
            sent += len(documents)
            documents.clear()
    if documents:
        send_batch(uri, token, documents)
        sent += len(documents)

    manifest = {
        "schema_version": 1,
        "replay_id": replay_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dataset_owner": "Splunk Attack Data",
        "target_host": "WIN10-LAB01",
        "event_count": sent,
        "scenarios": [
            {
                "name": scenario.name,
                "mitre_technique": scenario.technique,
                "event_count": scenario_counts[scenario.name],
                "index": scenario.index,
                "sourcetype": scenario.sourcetype,
                "source_url": scenario.url,
            }
            for scenario in (*SCENARIOS, BASELINE)
        ],
        "security": {
            "hec_token_persisted": False,
            "raw_events_published": False,
            "private_addresses_published": False,
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hec-uri", default="https://127.0.0.1:18088")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--replay-id", default=datetime.now().strftime("campaign-%Y%m%d-%H%M%S"))
    args = parser.parse_args()
    token = os.environ.pop("HEC_TOKEN", "")
    if not token:
        print("ERROR: HEC_TOKEN is required", file=sys.stderr)
        return 2
    try:
        manifest = replay(args.hec_uri, token, args.output, args.replay_id)
    except (HTTPError, URLError, TimeoutError, RuntimeError, ValueError) as error:
        print(f"ERROR: replay failed: {error}", file=sys.stderr)
        return 1
    finally:
        token = ""
    print(f"OK: replayed {manifest['event_count']} events across {len(manifest['scenarios'])} scenarios")
    print(f"OK: wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
