"""The inline gateway: an OpenAI-compatible /v1/chat/completions proxy in front of any model, plus the
policy decision endpoints an MCP proxy or agent framework calls around each tool call.

Resilience controls sit before the content checks, in the order a request meets them: body size limit,
global rate limit, load shedding at a concurrency ceiling, then the engine. External filters (a hosted
classifier, a DLP service) run under an enforcement timeout; on timeout the agent's profile decides whether
the gateway fails open or closed.
"""
from __future__ import annotations

import asyncio
import hmac
import os
import time
from pathlib import Path
from typing import Awaitable, Callable

import httpx
import yaml
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from .audit import AuditLog
from .engine import Decision, Engine, Finding

ExternalFilter = Callable[[str], Awaitable[bool]]     # returns True when the text should be blocked
Upstream = Callable[[list[dict], dict], Awaitable[str]]


class TokenBucket:
    def __init__(self, rate: float, burst: int, clock=time.monotonic):
        self.rate, self.burst, self.clock = rate, burst, clock
        self.tokens, self.at = float(burst), clock()

    def take(self) -> bool:
        now = self.clock()
        self.tokens = min(self.burst, self.tokens + (now - self.at) * self.rate)
        self.at = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


async def mock_upstream(messages: list[dict], params: dict) -> str:
    return "Here is a summary of your request: " + str(messages[-1].get("content", ""))[:200]


def http_upstream(url: str, api_key: str, model: str) -> Upstream:
    """Any OpenAI-compatible endpoint: Azure OpenAI / AI Foundry, a Bedrock access gateway, vLLM, LiteLLM."""
    async def call(messages, params):
        async with httpx.AsyncClient(timeout=60) as c:
            r = await c.post(url, headers={"Authorization": f"Bearer {api_key}"},
                             json={"model": model, "messages": messages, **params})
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
    return call


def secret(name: str) -> str:
    """NAME_FILE (a mounted secret file) wins over NAME (an env var), so Kubernetes can mount secrets as files."""
    f = os.environ.get(name + "_FILE")
    return Path(f).read_text(encoding="utf-8").strip() if f else os.environ.get(name, "")


def load_policy(path: str | Path) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def create_app(policy: dict, log: AuditLog, upstream: Upstream = mock_upstream,
               external_filter: ExternalFilter | None = None, admin_token: str | None = None) -> FastAPI:
    app = FastAPI(title="Tripwire AI gateway")
    eng = Engine(policy, log)
    gw = policy["gateway"]
    bucket = TokenBucket(gw["global_rps"], gw["global_burst"])
    slots = asyncio.Semaphore(gw["max_concurrency"])
    admin_token = admin_token or secret("TRIPWIRE_ADMIN_TOKEN")
    app.state.engine = eng

    def deny(d: Decision):
        return JSONResponse({"error": {"type": "policy_violation", "reason": d.reason(), "request_id": d.request_id}},
                            status_code=d.status)

    @app.middleware("http")
    async def resilience(request: Request, call_next):
        if request.url.path.startswith("/v1/admin") or request.url.path == "/healthz":
            return await call_next(request)
        if int(request.headers.get("content-length") or 0) > gw["max_body_bytes"]:
            return JSONResponse({"error": {"type": "body_too_large"}}, status_code=413)
        if not bucket.take():
            return JSONResponse({"error": {"type": "rate_limited", "scope": "global"}}, status_code=429,
                                headers={"Retry-After": "1"})
        if slots.locked():
            return JSONResponse({"error": {"type": "overloaded"}}, status_code=503, headers={"Retry-After": "2"})
        async with slots:
            return await call_next(request)

    async def external_check(d: Decision, text: str):
        """Run the external filter under the enforcement timeout; the profile decides fail-open vs closed."""
        if external_filter is None or d.blocked:
            return
        prof = policy["profiles"][policy["agents"][d.agent_id]["profile"]]
        try:
            hit = await asyncio.wait_for(external_filter(text), gw["enforcement_timeout_ms"] / 1000)
            if hit:
                d.findings.append(Finding("injection", "external_classifier", prof["modes"].get("injection", "block")))
        except asyncio.TimeoutError:
            mode = "block" if prof["on_timeout"] == "block" else "detect"
            d.findings.append(Finding("timeout", "external_filter_timeout", mode))
        if any(f.mode == "block" for f in d.findings):
            d.action, d.status = "block", 503 if any(f.category == "timeout" for f in d.findings) else 403

    @app.post("/v1/chat/completions")
    async def chat(body: dict, x_agent_id: str = Header(""), x_session_id: str = Header("default")):
        messages = body.get("messages") or []
        params = {k: v for k, v in body.items() if k in ("max_tokens", "temperature", "thinking_budget")}
        d = eng.check_prompt(x_agent_id, x_session_id, messages, params)
        if not d.blocked:
            await external_check(d, "\n".join(str(m.get("content", "")) for m in messages if m.get("role") != "system"))
        if d.blocked:
            return deny(d)
        text = await upstream(d.payload["messages"], d.payload["params"])
        system = "\n".join(str(m.get("content", "")) for m in messages if m.get("role") == "system")
        o = eng.check_output(x_agent_id, x_session_id, text, system)
        if o.blocked:
            return deny(o)
        return {"id": d.request_id, "object": "chat.completion",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": o.payload}, "finish_reason": "stop"}],
                "tripwire": {"findings": [f.__dict__ for f in d.findings + o.findings]}}

    @app.post("/v1/tools/call")
    async def tool_call(body: dict, x_agent_id: str = Header(""), x_session_id: str = Header("default")):
        d = eng.check_tool_call(x_agent_id, x_session_id, body.get("tool", ""), body.get("args") or {})
        if d.blocked:
            return deny(d)
        return {"decision": "allow", "request_id": d.request_id, "findings": [f.__dict__ for f in d.findings]}

    @app.post("/v1/tools/result")
    async def tool_result(body: dict, x_agent_id: str = Header(""), x_session_id: str = Header("default")):
        d = eng.check_tool_result(x_agent_id, x_session_id, body.get("tool", ""), str(body.get("content", "")))
        return {"decision": d.action, "content": d.payload, "request_id": d.request_id}

    # ------------------------------------------------------------------ admin: containment and inventory
    def admin(token: str):
        if not admin_token or not hmac.compare_digest(token, admin_token):
            raise HTTPException(401, "admin token required")

    @app.post("/v1/admin/agents/{agent_id}/quarantine")
    async def quarantine(agent_id: str, x_admin_token: str = Header("")):
        admin(x_admin_token)
        if agent_id not in policy["agents"]:
            raise HTTPException(404, "unknown agent")
        eng.quarantine(agent_id, "manual")
        return {"agent": agent_id, "status": "quarantined"}

    @app.post("/v1/admin/agents/{agent_id}/release")
    async def release(agent_id: str, x_admin_token: str = Header("")):
        admin(x_admin_token)
        eng.release(agent_id)
        return {"agent": agent_id, "status": "active"}

    @app.post("/v1/admin/kill-switch")
    async def kill(body: dict, x_admin_token: str = Header("")):
        admin(x_admin_token)
        eng.set_kill_switch(bool(body.get("on")))
        return {"kill_switch": policy["kill_switch"]}

    @app.get("/v1/admin/inventory")
    async def inventory(x_admin_token: str = Header("")):
        admin(x_admin_token)
        return [{"agent": a, "owner": c["owner"], "profile": c["profile"], "blast_radius": c["blast_radius"],
                 "tools": c["tools"], "status": "quarantined" if a in eng.quarantined else "active",
                 "recent_strikes": len(eng.strikes.get(a, []))} for a, c in policy["agents"].items()]

    @app.get("/healthz")
    async def health():
        return {"ok": True, "policy_version": policy.get("version"), "kill_switch": policy.get("kill_switch")}

    return app


def default_app() -> FastAPI:   # uvicorn --factory tripwire.gateway:default_app
    policy = load_policy(os.environ.get("TRIPWIRE_POLICY", "policy/policy.yaml"))
    log = AuditLog(os.environ.get("TRIPWIRE_LOG", "logs/decisions.jsonl"))
    up = mock_upstream
    if os.environ.get("TRIPWIRE_UPSTREAM_URL"):
        up = http_upstream(os.environ["TRIPWIRE_UPSTREAM_URL"], secret("TRIPWIRE_UPSTREAM_KEY"),
                           os.environ.get("TRIPWIRE_UPSTREAM_MODEL", "gpt-4o-mini"))
    return create_app(policy, log, up)
