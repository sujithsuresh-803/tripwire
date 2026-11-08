"""Decision log. One JSON line per decision, flat and typed so it loads into Sentinel (a custom table via
the Logs Ingestion API) or Splunk (HEC) without a parser. Inputs are PII-redacted before they are written;
they are kept so a past decision can be replayed against a new policy.
"""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from .taxonomy import tags

_SEV = {"low": 0, "medium": 1, "high": 2}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class AuditLog:
    def __init__(self, path: str | Path | None):
        self.path = Path(path) if path else None
        self.lines: list[dict] = []
        self._lock = threading.Lock()

    def _write(self, rec: dict):
        with self._lock:
            self.lines.append(rec)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def decision(self, d, agent: dict, session_id: str, record: dict, policy_version):
        t = [tags(f.category) for f in d.findings]
        sev = max((x["severity"] for x in t), key=_SEV.get, default="none")
        body = json.dumps(record, sort_keys=True, ensure_ascii=False)
        self._write({
            "TimeGenerated": _now(), "EventType": "decision", "RequestId": d.request_id, "Kind": d.kind,
            "AgentId": d.agent_id, "Owner": agent.get("owner", ""), "Profile": agent.get("profile", ""),
            "BlastRadius": agent.get("blast_radius", ""), "SessionId": session_id, "Action": d.action,
            "Status": d.status, "Severity": sev,
            "Categories": sorted({f.category for f in d.findings}),
            "Rules": [f"{f.category}:{f.rule}:{f.mode}" for f in d.findings],
            "OwaspLlm": sorted({x["owasp_llm"] for x in t if x["owasp_llm"]}),
            "OwaspAgentic": sorted({x["owasp_agentic"] for x in t if x["owasp_agentic"]}),
            "Atlas": sorted({x["atlas"] for x in t if x["atlas"]}),
            "DetectOnly": [f.category for f in d.findings if f.mode == "detect"],
            "InputHash": hashlib.sha256(body.encode()).hexdigest()[:24],
            "Input": record, "PolicyVersion": policy_version,
        })

    def containment(self, agent_id: str, action: str, reason: str, by: str, agent: dict, **extra):
        self._write({"TimeGenerated": _now(), "EventType": "containment", "AgentId": agent_id,
                     "Owner": agent.get("owner", ""), "BlastRadius": agent.get("blast_radius", ""),
                     "Action": action, "Reason": reason, "By": by, **{"".join(p.title() for p in k.split("_")): v for k, v in extra.items()}})


def read(path: str | Path) -> list[dict]:
    return [json.loads(x) for x in Path(path).read_text(encoding="utf-8").splitlines() if x.strip()]
