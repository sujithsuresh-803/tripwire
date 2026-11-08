"""The closed loop: red-team misses -> candidate policy -> re-test -> human review -> merge.

    python -m tripwire.loop                  # propose policy/candidate.yaml and print the before/after
    python -m tripwire.loop --apply          # after review: write the candidate over policy/policy.yaml

Two kinds of fix are proposed, both as policy data, never code:
  1. Rule weights. A detector rule that fired on a missed attack but scored under the threshold, and fires on
     no benign input, is raised to the threshold.
  2. Phrases. For misses no rule saw at all, the shortest word n-gram shared by the most misses and absent from
     every benign input is added to injection.extra_phrases.
A candidate is kept only if it blocks no benign input. The held-out suite (never mined) shows whether the fix
generalises or just memorised the attacks it came from.
"""
from __future__ import annotations

import argparse
import copy
import re
from pathlib import Path

import yaml

from .injection import normalise, scan_injection
from .redteam import load, run_suites

STOP = set("a an the and or to of in on for with this that it is are be you your my me i we our all any "
           "from as at by then now do does what it's".split())
ROOT = Path(__file__).resolve().parent.parent


def _words(text: str) -> list[str]:
    return re.findall(r"[\w|<>]+", normalise(text).lower())


def _ngrams(words: list[str], lo=2, hi=4) -> set[str]:
    out = set()
    for n in range(lo, hi + 1):
        for i in range(len(words) - n + 1):
            g = words[i:i + n]
            if sum(w not in STOP for w in g) >= 2:
                out.add(" ".join(g))
    return out


def propose(policy: dict, attacks: list[dict], benign: list[dict]) -> tuple[dict, list[str]]:
    res = run_suites(policy, attacks, benign)
    cand = copy.deepcopy(policy)
    inj = cand.setdefault("injection", {})
    inj["rule_weights"] = dict(inj.get("rule_weights") or {})
    inj["extra_phrases"] = list(inj.get("extra_phrases") or [])
    thr = inj.get("threshold", 1.0)
    notes = []
    benign_text = [c.get("input", "") for c in benign if c.get("input")]
    benign_rules = {r for t in benign_text for r in scan_injection(t).rules}

    unseen = []
    for m in res["missed"]:
        rules = scan_injection(m["input"]).rules
        safe = [r for r in rules if r not in benign_rules]
        if safe:
            for r in safe:
                if inj["rule_weights"].get(r, 0) < thr:
                    inj["rule_weights"][r] = thr
                    notes.append(f"weight  {r} -> {thr}  (fired under threshold on {m['id']}, on 0 benign)")
        elif m["input"]:
            unseen.append(m)

    benign_grams = set().union(*(_ngrams(_words(t)) for t in benign_text))
    grams = {m["id"]: _ngrams(_words(m["input"])) - benign_grams for m in unseen}
    left = set(grams)
    while left:
        count: dict[str, int] = {}
        for i in left:
            for g in grams[i]:
                count[g] = count.get(g, 0) + 1
        if not count:
            break
        best = min(count, key=lambda g: (-count[g], len(g.split()), g))
        inj["extra_phrases"].append(best)
        covered = {i for i in left if best in grams[i]}
        notes.append(f"phrase  '{best}'  (covers {', '.join(sorted(covered))}; in 0 benign)")
        left -= covered
    return cand, notes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", default=str(ROOT / "policy/policy.yaml"))
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()
    policy = yaml.safe_load(Path(a.policy).read_text(encoding="utf-8"))
    atk, ben, held = (load(ROOT / f"redteam/{n}.yaml") for n in ("attacks", "benign", "heldout"))
    cand, notes = propose(policy, atk, ben)
    before, after = run_suites(policy, atk, ben), run_suites(cand, atk, ben)
    hb, ha = run_suites(policy, held, []), run_suites(cand, held, [])
    print("proposed changes:")
    for n in notes or ["(none: every attack is already defended)"]:
        print("  " + n)
    print(f"\n{'':22}{'current':>10}{'candidate':>12}")
    print(f"{'attacks succeeding':22}{before['attacks_succeeded']:>7}/{before['attacks']:<3}{after['attacks_succeeded']:>8}/{after['attacks']}")
    print(f"{'held-out succeeding':22}{hb['attacks_succeeded']:>7}/{hb['attacks']:<3}{ha['attacks_succeeded']:>8}/{ha['attacks']}")
    print(f"{'benign blocked':22}{before['benign_blocked']:>7}/{before['benign']:<3}{after['benign_blocked']:>8}/{after['benign']}")
    for m in ha["missed"]:
        print(f"  still missed (held-out): {m['id']} {m['input'][:70]}")
    if after["benign_blocked"] > before["benign_blocked"]:
        print("\nrejected: the candidate blocks benign traffic")
        return 1
    out = Path(a.policy) if a.apply else Path(a.policy).with_name("candidate.yaml")
    if a.apply:
        cand["version"] = int(policy.get("version", 0)) + 1
        text = Path(a.policy).read_text(encoding="utf-8")
        inj = cand["injection"]
        text = re.sub(r"(?m)^version: \d+", f"version: {cand['version']}", text)
        text = re.sub(r"(?m)^  rule_weights: .*$", "  rule_weights: " + yaml.safe_dump(inj["rule_weights"], default_flow_style=True).strip()
                      + "   # merged from loop.py", text)
        text = re.sub(r"(?m)^  extra_phrases: .*$", "  extra_phrases: " + yaml.safe_dump(inj["extra_phrases"], default_flow_style=True, width=1000).strip()
                      + "   # merged from loop.py", text)
        out.write_text(text, encoding="utf-8")
    else:
        out.write_text(yaml.safe_dump(cand, sort_keys=False, allow_unicode=True), encoding="utf-8")
    print(f"\nwrote {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
