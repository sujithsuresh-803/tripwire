"""The policy decision point. The gateway asks it about four things: a prompt on its way to a model, a
tool call on its way to an MCP server, a tool result on its way back into the context, and a model output on
its way to the user. Every answer is logged with the agent's owner, blast radius and threat tags.
"""
from __future__ import annotations

import copy
import re
import time
import uuid
from collections import deque
from dataclasses import dataclass, field

from . import detectors as D
from .audit import AuditLog
from .injection import normalise
from .taxonomy import tags

SEVERITY = {"low": 0, "medium": 1, "high": 2}
WITHHELD = "[withheld by tripwire: this tool output contained instructions aimed at the model]"


@dataclass
class Finding:
    category: str
    rule: str
    mode: str                       # block | detect | redact
    detail: str = ""


@dataclass
class Decision:
    kind: str
    agent_id: str
    action: str = "allow"           # allow | block
    status: int = 200
    findings: list[Finding] = field(default_factory=list)
    payload: object = None          # rewritten messages / text / params when the policy changed them
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])

    @property
    def blocked(self) -> bool:
        return self.action == "block"

    def reason(self) -> str:
        hard = [f for f in self.findings if f.mode == "block"]
        return ", ".join(sorted({f.category for f in hard})) or "allowed"


class Engine:
    def __init__(self, policy: dict, log: AuditLog | None = None, clock=time.monotonic):
        self.policy = policy
        self.log = log or AuditLog(None)
        self.clock = clock
        self.sessions: dict[str, set[str]] = {}
        self.quarantined: dict[str, dict] = {}
        self.strikes: dict[str, deque] = {}
        self.usage: dict[str, deque] = {}

    # ------------------------------------------------------------------ helpers
    def _agent(self, agent_id: str) -> dict | None:
        return self.policy["agents"].get(agent_id)

    def _profile(self, agent: dict) -> dict:
        return self.policy["profiles"][agent["profile"]]

    def _mode(self, prof: dict, category: str) -> str:
        return prof["modes"].get(category, "block")

    def _scan(self, text: str) -> dict[str, list[str]]:
        inj = self.policy.get("injection", {})
        return D.scan_text(text, inj.get("threshold", 1.0), inj.get("extra_phrases") or [], inj.get("rule_weights"))

    def _gate(self, d: Decision, agent: dict | None) -> bool:
        """Identity, kill switch and quarantine come before any content check."""
        if agent is None:
            d.findings.append(Finding("scope", "unregistered_agent", "block"))
            d.status = 403
        elif self.policy.get("kill_switch"):
            d.findings.append(Finding("kill_switch", "global_kill_switch", "block"))
            d.status = 503
        elif d.agent_id in self.quarantined:
            d.findings.append(Finding("quarantined", self.quarantined[d.agent_id]["reason"], "block"))
            d.status = 403
        else:
            return True
        d.action = "block"
        return False

    def _finish(self, d: Decision, session_id: str, record: dict) -> Decision:
        if any(f.mode == "block" for f in d.findings):
            d.action = "block"
            if d.status == 200:
                d.status = 403
        agent = self._agent(d.agent_id) or {}
        self.log.decision(d, agent, session_id, record, self.policy.get("version"))
        if d.blocked and d.agent_id in self.policy["agents"] and d.agent_id not in self.quarantined:
            self._strike(d, agent)
        return d

    def _strike(self, d: Decision, agent: dict):
        if not any(tags(f.category)["severity"] == "high" and f.mode == "block" for f in d.findings):
            return
        if any(f.category in ("kill_switch", "quarantined") for f in d.findings):
            return
        c = self.policy["containment"]
        now = self.clock()
        q = self.strikes.setdefault(d.agent_id, deque())
        q.append(now)
        while q and now - q[0] > c["window_s"]:
            q.popleft()
        if len(q) >= c["auto_quarantine_after"]:
            self.quarantine(d.agent_id, "auto:repeated_high_severity", by="tripwire",
                            time_to_contain_s=round(now - q[0], 3))

    # ------------------------------------------------------------------ containment
    def quarantine(self, agent_id: str, reason: str, by: str = "admin", **extra):
        self.quarantined[agent_id] = {"reason": reason, "since": self.clock(), "by": by}
        self.log.containment(agent_id, "quarantine", reason, by, self._agent(agent_id) or {}, **extra)

    def release(self, agent_id: str, by: str = "admin"):
        if self.quarantined.pop(agent_id, None) is not None:
            self.strikes.pop(agent_id, None)
            self.log.containment(agent_id, "release", "manual", by, self._agent(agent_id) or {})

    def set_kill_switch(self, on: bool, by: str = "admin"):
        self.policy["kill_switch"] = bool(on)
        self.log.containment("*", "kill_switch_on" if on else "kill_switch_off", "manual", by, {})

    # ------------------------------------------------------------------ prompts
    def check_prompt(self, agent_id: str, session_id: str, messages: list[dict], params: dict | None = None) -> Decision:
        d = Decision("prompt", agent_id)
        agent = self._agent(agent_id)
        record = {"messages": [{"role": m.get("role"), "content": D.redact_pii(str(m.get("content", "")))[0][:4000]}
                               for m in messages], "params": params or {}}
        if not self._gate(d, agent):
            return self._finish(d, session_id, record)
        prof = self._profile(agent)
        messages = copy.deepcopy(messages)
        params = dict(params or {})

        # unbounded consumption: prompt budget, tokens per minute, output and thinking caps
        total = sum(D.approx_tokens(str(m.get("content", ""))) for m in messages)
        if total > prof["max_prompt_tokens"]:
            if prof.get("truncate"):
                messages = _truncate(messages, prof["max_prompt_tokens"])
                d.findings.append(Finding("prompt_budget", "truncated", "redact", f"{total} tokens"))
                total = sum(D.approx_tokens(str(m.get("content", ""))) for m in messages)
            else:
                d.findings.append(Finding("prompt_budget", "over_budget", "block", f"{total} tokens"))
                d.status = 413
                return self._finish(d, session_id, record)
        if not self._spend(agent_id, total, prof["tokens_per_minute"]):
            d.findings.append(Finding("rate_limit", "tokens_per_minute", "block"))
            d.status = 429
            return self._finish(d, session_id, record)
        for key, cap in (("max_tokens", "max_output_tokens"), ("thinking_budget", "max_thinking_tokens")):
            if params.get(key) and params[key] > prof[cap]:
                d.findings.append(Finding("overload", f"{key}_capped", "redact", f"{params[key]} -> {prof[cap]}"))
                params[key] = prof[cap]
        params.setdefault("max_tokens", prof["max_output_tokens"])

        for m in messages:
            text = str(m.get("content", ""))
            role = m.get("role")
            if role == "system":
                continue
            for cat, rules in self._scan(text).items():
                if role == "tool" and cat in ("injection", "jailbreak", "prompt_leak"):
                    cat = "indirect_injection"
                for r in rules:
                    d.findings.append(Finding(cat, r, self._mode(prof, cat)))
            if role == "user":
                mode = self._mode(prof, "pii")
                if mode != "off":
                    red, found = D.redact_pii(text)
                    if found:
                        d.findings.append(Finding("pii", ",".join(sorted({f.kind for f in found})), mode))
                        if mode == "redact":
                            m["content"] = red
        d.payload = {"messages": messages, "params": params}
        return self._finish(d, session_id, record)

    def _spend(self, agent_id: str, tokens: int, per_minute: int) -> bool:
        now = self.clock()
        q = self.usage.setdefault(agent_id, deque())
        while q and now - q[0][0] > 60:
            q.popleft()
        if sum(t for _, t in q) + tokens > per_minute:
            return False
        q.append((now, tokens))
        return True

    # ------------------------------------------------------------------ tools (MCP)
    def check_tool_call(self, agent_id: str, session_id: str, tool: str, args: dict) -> Decision:
        d = Decision("tool_call", agent_id)
        agent = self._agent(agent_id)
        record = {"tool": tool, "args": {k: D.redact_pii(str(v))[0][:1000] for k, v in (args or {}).items()}}
        if not self._gate(d, agent):
            return self._finish(d, session_id, record)
        prof = self._profile(agent)
        spec = self.policy["tools"].get(tool)
        if spec is None or tool not in agent["tools"]:
            d.findings.append(Finding("tool_not_allowed", tool, "block"))
            return self._finish(d, session_id, record)
        if spec["server"] not in agent["mcp_servers"]:
            d.findings.append(Finding("mcp_server", spec["server"], "block"))
        if spec["scope"] not in agent["scopes"]:
            d.findings.append(Finding("scope", spec["scope"], "block"))
        caps = set(spec.get("capabilities", []))
        for name, rule in (spec.get("args") or {}).items():
            val = str((args or {}).get(name, ""))
            bad = (rule.get("pattern") and not re.search(rule["pattern"], val)) or \
                  (rule.get("deny") and re.search(rule["deny"], val)) or len(val) > rule.get("max_len", 10000)
            if bad:
                d.findings.append(Finding("code_exec" if "code_exec" in caps else "tool_args", name, "block"))
        if spec.get("scan_args"):
            for name, val in (args or {}).items():
                for cat in self._scan(str(val)):
                    if cat in ("injection", "jailbreak", "prompt_leak"):
                        d.findings.append(Finding("memory_poisoning", name, "block"))
        if "egress" in caps:
            for name, val in (args or {}).items():
                found = self._scan(str(val))
                if "secrets" in found:
                    d.findings.append(Finding("secrets", ",".join(found["secrets"]), "block"))
            flags = self.sessions.get(session_id, set())
            if {"private_data", "untrusted_content"} <= flags:
                d.findings.append(Finding("trifecta", "private+untrusted+egress", prof.get("trifecta", "block"),
                                          "session already read private data and untrusted content"))
        d = self._finish(d, session_id, record)
        if not d.blocked:
            self.sessions.setdefault(session_id, set()).update(caps & {"private_data", "untrusted_content"})
        return d

    def check_tool_result(self, agent_id: str, session_id: str, tool: str, content: str) -> Decision:
        d = Decision("tool_result", agent_id)
        agent = self._agent(agent_id)
        record = {"tool": tool, "content": D.redact_pii(content)[0][:4000]}
        if not self._gate(d, agent):
            return self._finish(d, session_id, record)
        prof = self._profile(agent)
        cat_for = "memory_poisoning" if tool.startswith("memory/") else \
                  "rag_poisoning" if tool.startswith(("kb/", "search/")) else "indirect_injection"
        for cat, rules in self._scan(content).items():
            if cat in ("injection", "jailbreak", "prompt_leak"):
                for r in rules:
                    d.findings.append(Finding(cat_for, r, self._mode(prof, "indirect_injection")))
            elif cat == "secrets":
                d.findings.append(Finding("secrets", ",".join(rules), self._mode(prof, "secrets")))
        if D.find_pii(content):
            self.sessions.setdefault(session_id, set()).add("private_data")
        d = self._finish(d, session_id, record)
        d.payload = WITHHELD if d.blocked else content
        return d

    # ------------------------------------------------------------------ outputs
    def check_output(self, agent_id: str, session_id: str, text: str, system_prompt: str = "") -> Decision:
        d = Decision("output", agent_id)
        agent = self._agent(agent_id)
        record = {"output": D.redact_pii(text)[0][:4000]}
        if not self._gate(d, agent):
            return self._finish(d, session_id, record)
        prof = self._profile(agent)
        for cat, rules in D.scan_output(text).items():
            d.findings.append(Finding(cat, ",".join(rules), self._mode(prof, cat)))
        if system_prompt and _leaks(system_prompt, text):
            d.findings.append(Finding("prompt_leak", "system_prompt_in_output", self._mode(prof, "prompt_leak")))
        mode = self._mode(prof, "pii")
        red, found = D.redact_pii(text)
        if found and mode != "off":
            d.findings.append(Finding("pii", ",".join(sorted({f.kind for f in found})), mode))
            if mode == "redact":
                text = red
        d.payload = text
        return self._finish(d, session_id, record)


def _truncate(messages: list[dict], budget: int) -> list[dict]:
    """Keep system messages and as many of the newest messages as fit; cut the oldest that remains."""
    system = [m for m in messages if m.get("role") == "system"]
    used = sum(D.approx_tokens(str(m.get("content", ""))) for m in system)
    kept: list[dict] = []
    for m in reversed([m for m in messages if m.get("role") != "system"]):
        t = D.approx_tokens(str(m.get("content", "")))
        if used + t > budget:
            room = (budget - used) * 4
            if room > 200 and not kept:
                kept.append(dict(m, content=str(m["content"])[-room:]))
            break
        kept.append(m)
        used += t
    return system + list(reversed(kept))


def _leaks(system_prompt: str, output: str, n: int = 8) -> bool:
    """True if any run of n consecutive words from the system prompt appears in the output."""
    sw = normalise(system_prompt).lower().split()
    out = " " + " ".join(normalise(output).lower().split()) + " "
    return any(" " + " ".join(sw[i:i + n]) + " " in out for i in range(max(0, len(sw) - n + 1)))
