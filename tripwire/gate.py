"""CI gate: run every suite, write redteam/results.json, exit 1 if any attack succeeds or benign traffic is blocked.

    python -m tripwire.gate
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from .redteam import load, run_suites, with_modes

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    policy = yaml.safe_load((ROOT / "policy/policy.yaml").read_text(encoding="utf-8"))
    atk, ben = load(ROOT / "redteam/attacks.yaml"), load(ROOT / "redteam/benign.yaml")
    main_run = run_suites(policy, atk, ben)
    held = {n: run_suites(policy, load(ROOT / f"redteam/{n}.yaml"), []) for n in ("heldout", "heldout_v2")}
    modes = {m: run_suites(with_modes(policy, m), atk, ben) for m in ("detect", "block")}

    print(f"policy v{policy['version']}")
    print(f"attacks   {main_run['attacks'] - main_run['attacks_succeeded']}/{main_run['attacks']} defended")
    print(f"benign    {main_run['benign'] - main_run['benign_blocked']}/{main_run['benign']} allowed "
          f"({main_run['benign_alerts']} raised a detect-mode alert)")
    for n, r in held.items():
        print(f"{n:<12}{r['attacks'] - r['attacks_succeeded']}/{r['attacks']} defended (not gated, reported)")
    print("by OWASP  " + "  ".join(f"{k} {v}" for k, v in main_run["by_owasp"].items()))
    print("\nall content rules in one mode (pii stays redact):")
    for m, r in modes.items():
        print(f"  {m:<7} attacks through {r['attacks_succeeded']:>2}/{r['attacks']}   benign blocked "
              f"{r['benign_blocked']}/{r['benign']}   benign alerts {r['benign_alerts']}")

    strip = lambda r: {k: v for k, v in r.items() if k not in ("attack_results", "benign_results")}
    out = {"policy_version": policy["version"], "main": strip(main_run),
           "heldout": {n: strip(r) for n, r in held.items()}, "modes": {m: strip(r) for m, r in modes.items()},
           "attacks": main_run["attack_results"]}
    (ROOT / "redteam/results.json").write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    ok = main_run["attacks_succeeded"] == 0 and main_run["benign_blocked"] == 0
    print("\nGATE " + ("PASS" if ok else "FAIL: " + ", ".join(m["id"] for m in main_run["missed"] + main_run["false_positives"])))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
