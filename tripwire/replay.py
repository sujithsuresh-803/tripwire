"""Decision replay for forensics: re-run a logged decision against the current (or a candidate) policy.

    python -m tripwire.replay logs/decisions.jsonl <request_id> [--policy policy/candidate.yaml]
    python -m tripwire.replay logs/decisions.jsonl --all-allowed      # which past allows would now be blocked?

Answers the two questions an incident review asks: why was this allowed, and would today's policy stop it.
Inputs in the log are PII-redacted, so a replay sees what the log saw. Session state (trifecta flags) is
rebuilt from the same session's earlier tool calls in the log.
"""
from __future__ import annotations

import argparse
import copy
import re
from pathlib import Path

import yaml

from .audit import read
from .engine import Engine

ROOT = Path(__file__).resolve().parent.parent
_REDACTED = re.compile(r"\[(EMAIL|PHONE|CARD|AADHAAR|PAN|IFSC)\]")


def replay(lines: list[dict], rec: dict, policy: dict) -> dict:
    eng = Engine(copy.deepcopy(policy))
    sess, inp = rec["SessionId"], rec["Input"]
    for prior in lines:            # rebuild session flags from earlier allowed tool calls
        if prior is rec:
            break
        if prior.get("SessionId") == sess and prior.get("Kind") == "tool_call" and prior.get("Action") == "allow":
            spec = policy["tools"].get(prior["Input"]["tool"], {})
            eng.sessions.setdefault(sess, set()).update(set(spec.get("capabilities", [])) & {"private_data", "untrusted_content"})
    kind = rec["Kind"]
    if kind == "prompt":
        d = eng.check_prompt(rec["AgentId"], sess, inp["messages"], inp.get("params"))
    elif kind == "tool_call":
        d = eng.check_tool_call(rec["AgentId"], sess, inp["tool"], inp["args"])
    elif kind == "tool_result":
        d = eng.check_tool_result(rec["AgentId"], sess, inp["tool"], inp["content"])
    else:
        d = eng.check_output(rec["AgentId"], sess, inp["output"])
    # an argument check on a value the log redacted can't be re-run honestly: report it, don't judge it
    hidden = {k for k, v in (inp.get("args") or {}).items() if _REDACTED.search(str(v))}
    unverifiable = [f for f in d.findings if f.category == "tool_args" and f.rule in hidden]
    kept = [f for f in d.findings if f not in unverifiable]
    now = "block" if any(f.mode == "block" for f in kept) else "allow"
    return {"request_id": rec["RequestId"], "kind": kind, "agent": rec["AgentId"],
            "was": rec["Action"], "now": now, "was_rules": rec["Rules"],
            "now_rules": [f"{f.category}:{f.rule}:{f.mode}" for f in kept],
            "unverifiable": [f"{f.category}:{f.rule} (redacted in log)" for f in unverifiable],
            "policy_then": rec.get("PolicyVersion"), "policy_now": policy.get("version")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("request_id", nargs="?")
    ap.add_argument("--policy", default=str(ROOT / "policy/policy.yaml"))
    ap.add_argument("--all-allowed", action="store_true")
    a = ap.parse_args()
    policy = yaml.safe_load(Path(a.policy).read_text(encoding="utf-8"))
    lines = [x for x in read(a.log) if x.get("EventType") == "decision"]
    targets = [x for x in lines if x["Action"] == "allow"] if a.all_allowed else \
              [x for x in lines if x["RequestId"] == a.request_id]
    if not targets:
        raise SystemExit("no matching decisions")
    for rec in targets:
        r = replay(lines, rec, policy)
        if a.all_allowed and r["now"] == "allow":
            continue
        flag = "CHANGED" if r["was"] != r["now"] else "same"
        print(f"{r['request_id']}  {r['kind']:<11} {r['agent']:<15} v{r['policy_then']}: {r['was']:<5} -> "
              f"v{r['policy_now']}: {r['now']:<5} [{flag}]  {', '.join(r['now_rules'] + r['unverifiable']) or '-'}")


if __name__ == "__main__":
    main()
