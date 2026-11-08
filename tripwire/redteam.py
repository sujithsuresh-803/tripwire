"""Runs the red-team and benign suites against a policy. Used by the CI gate, the closed loop and the tests."""
from __future__ import annotations

import copy
from collections import Counter
from pathlib import Path

import yaml

from .engine import Engine

SYSTEM = "You are an internal assistant for the demo tenant. Follow company policy."


def load(path: str | Path) -> list[dict]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def _text(case: dict) -> str:
    return case["input"] * case.get("repeat_input", 1)


def run_case(policy: dict, case: dict) -> dict:
    """Fresh engine per case, so one case's strikes or quarantine can't help the next."""
    eng = Engine(copy.deepcopy(policy))
    kind, agent = case.get("kind", "prompt"), case["agent"]
    blocked, leaked, detected, cats = False, False, False, []

    def note(d):
        nonlocal blocked, detected
        blocked |= d.blocked
        detected |= any(f.mode == "detect" for f in d.findings)
        cats.extend(f.category for f in d.findings)

    if kind in ("prompt", "flood"):
        for _ in range(case.get("times", 1)):
            msgs = [{"role": "system", "content": SYSTEM}, {"role": case.get("input_role", "user"), "content": _text(case)}]
            d = eng.check_prompt(agent, "s1", msgs, {})
            note(d)
            if d.payload and case.get("forbidden"):
                leaked |= any(case["forbidden"] in str(m["content"]) for m in d.payload["messages"])
            if d.blocked:
                break
    elif kind == "output":
        d = eng.check_output(agent, "s1", _text(case), case.get("system", SYSTEM))
        note(d)
        leaked = bool(case.get("forbidden")) and case["forbidden"] in str(d.payload)
    elif kind == "tool_result":
        note(eng.check_tool_result(agent, "s1", case["tool"], _text(case)))
    elif kind == "sequence":
        for step in case["steps"]:
            d = eng.check_tool_call(agent, "s1", step["tool"], step.get("args", {}))
            note(d)
            if d.blocked:
                break
    if case.get("expect") == "redact":
        defended = not blocked and not leaked or blocked
    else:
        defended = blocked
    return {"id": case["id"], "owasp": case.get("owasp", ""), "kind": kind, "agent": agent, "defended": defended,
            "blocked": blocked, "detected": detected, "categories": sorted(set(cats)), "input": case.get("input", "")}


def run_suites(policy: dict, attacks: list[dict], benign: list[dict]) -> dict:
    a = [run_case(policy, c) for c in attacks]
    b = [run_case(policy, c) for c in benign]
    by = Counter(r["owasp"] for r in a)
    hit = Counter(r["owasp"] for r in a if r["defended"])
    return {
        "attacks": len(a), "attacks_succeeded": sum(not r["defended"] for r in a),
        "benign": len(b), "benign_blocked": sum(r["blocked"] for r in b),
        "benign_alerts": sum(r["detected"] for r in b),
        "by_owasp": {k: f"{hit[k]}/{by[k]}" for k in sorted(by)},
        "missed": [r for r in a if not r["defended"]],
        "false_positives": [r for r in b if r["blocked"]],
        "attack_results": a, "benign_results": b,
    }


def with_modes(policy: dict, mode: str) -> dict:
    """Same policy with every content rule set to one mode: used to measure detect vs block trade-offs."""
    p = copy.deepcopy(policy)
    for prof in p["profiles"].values():
        prof["modes"] = {k: (v if k == "pii" else mode) for k, v in prof["modes"].items()}
        if "trifecta" in prof:
            prof["trifecta"] = mode
    return p
