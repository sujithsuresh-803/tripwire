"""SOC detections over the decision log. The same logic ships as Sentinel KQL (detections/kql) and Splunk SPL
(detections/spl); this Python version runs in the tests so a rule change can't silently break a detection.

    python -m tripwire.detections logs/decisions.jsonl
"""
from __future__ import annotations

import sys
from collections import defaultdict
from datetime import datetime, timedelta

from .audit import read


def _t(r: dict) -> datetime:
    return datetime.fromisoformat(r["TimeGenerated"])


def _decisions(lines):
    return [r for r in lines if r.get("EventType") == "decision"]


def injection_burst(lines, n=3, window=timedelta(minutes=5)) -> list[dict]:
    """TW-001: one agent hit by >= n blocked prompt-injection (LLM01) decisions inside the window."""
    out, by = [], defaultdict(list)
    for r in _decisions(lines):
        if r["Action"] == "block" and "LLM01" in r["OwaspLlm"]:
            by[r["AgentId"]].append(r)
    for agent, rs in by.items():
        rs.sort(key=_t)
        for i in range(len(rs) - n + 1):
            if _t(rs[i + n - 1]) - _t(rs[i]) <= window:
                out.append({"rule": "TW-001", "agent": agent, "owner": rs[i]["Owner"], "count": n,
                            "first": rs[i]["TimeGenerated"], "severity": "high"})
                break
    return out


def trifecta_attempt(lines) -> list[dict]:
    """TW-002: an agent tried to send data out after reading private data and untrusted content."""
    return [{"rule": "TW-002", "agent": r["AgentId"], "session": r["SessionId"], "action": r["Action"],
             "severity": "high"} for r in _decisions(lines) if "trifecta" in r["Categories"]]


def campaign(lines, min_agents=2) -> list[dict]:
    """TW-003: the same blocked input hitting several agents (one attacker, many targets)."""
    by = defaultdict(set)
    for r in _decisions(lines):
        if r["Action"] == "block" and r["Kind"] in ("prompt", "tool_result"):
            by[r["InputHash"]].add(r["AgentId"])
    return [{"rule": "TW-003", "input_hash": h, "agents": sorted(a), "severity": "medium"}
            for h, a in by.items() if len(a) >= min_agents]


def detect_mode_volume(lines, threshold=20) -> list[dict]:
    """TW-004: many detect-only hits for one agent and category: either a real attack running in detect
    mode (move to block) or a noisy rule (tune it). Either way someone should look."""
    by = defaultdict(int)
    for r in _decisions(lines):
        for c in r.get("DetectOnly", []):
            by[(r["AgentId"], r["Profile"], c)] += 1
    return [{"rule": "TW-004", "agent": a, "profile": p, "category": c, "count": n, "severity": "low"}
            for (a, p, c), n in by.items() if n >= threshold]


def containment_events(lines) -> list[dict]:
    """TW-005: every quarantine, release and kill-switch change goes to the SOC queue."""
    return [{"rule": "TW-005", "agent": r["AgentId"], "action": r["Action"], "reason": r["Reason"],
             "by": r["By"], "time_to_contain_s": r.get("TimeToContainS"), "severity": "high"}
            for r in lines if r.get("EventType") == "containment"]


ALL = [injection_burst, trifecta_attempt, campaign, detect_mode_volume, containment_events]


def run(lines) -> list[dict]:
    return [a for f in ALL for a in f(lines)]


if __name__ == "__main__":
    for a in run(read(sys.argv[1])):
        print(a)
