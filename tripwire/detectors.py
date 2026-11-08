"""Content detectors. Each returns findings by category; the policy decides what a category does.

injection.py and pii.py come from Bastion (my guarded RAG project) unchanged. This module groups their
rules into the categories the policy is written in and adds secrets, overload and output-exfiltration checks.
"""
from __future__ import annotations

import re

from .injection import _RULES as _INJ_RULES, normalise, scan_injection
from .pii import find_pii, redact_pii

# Bastion rule -> policy category
_CATEGORY = {
    "override": "injection", "new_instructions": "injection", "addressed_to_ai": "injection",
    "chat_markup": "injection", "encoded_payload": "injection", "credential_request": "injection",
    "markdown_exfiltration": "injection", "jailbreak_persona": "jailbreak", "role_hijack": "jailbreak",
    "prompt_exfiltration": "prompt_leak",
}

_SECRETS = [(n, re.compile(p)) for n, p in [
    ("aws_access_key", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("anthropic_key", r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    ("openai_key", r"\bsk-(proj-)?[A-Za-z0-9_-]{32,}"),
    ("github_token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ("private_key", r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----"),
    ("azure_storage_key", r"AccountKey=[A-Za-z0-9+/=]{40,}"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("assigned_secret", r"(?i)\b(api[_-]?key|secret|passw(or)?d|client[_-]?secret)\s*[:=]\s*['\"]?[^\s'\"]{8,}"),
]]

_OVERLOAD = re.compile(
    r"\b(repeat|say|write|print|output)\b.{0,40}\b\d{3,}[\d,]* times\b"
    r"|\bcount (to|up to|from)\b.{0,20}\b\d{5,}"
    r"|\b(every|all) (possible )?(combination|permutation|path|move)s?\b.{0,60}\b(list|enumerate|evaluate|consider|check)\b"
    r"|\b(list|enumerate|evaluate|consider|check)\b.{0,40}\b(every|all) (possible )?(combination|permutation|path|move)s?\b"
    r"|\b(before answering|first),? (think|reason) (through|about) \d{3,}"
    r"|\brecursively (expand|explain|elaborate)\b.{0,40}\b(each|every)\b",
    re.I | re.S)

_EXFIL = re.compile(
    r"!\[[^\]]*\]\(\s*https?://[^)]+\)"                 # markdown image beacons
    r"|<img[^>]+src=['\"]?https?://"
    r"|https?://[^\s)]+[?&][\w-]+=[A-Za-z0-9+/_=%-]{24,}",  # data smuggled in a query string
    re.I)


def approx_tokens(text: str) -> int:
    return max(1, len(text) // 4)


_WEIGHTS = {name: w for name, w, _ in _INJ_RULES}

# Written by hand after loop.py's mined phrases missed two held-out families (see README, "The closed loop").
_TRIPWIRE_RULES = [(n, 1.0, re.compile(p, re.I | re.S)) for n, p in [
    # deferred execution: "translate / decode this, then do what it says"
    ("deferred_execution",
     r"\b(translate|decode|decrypt|convert|unscramble|read)\b.{0,60}\b(then|and)\s+(carry (it|them) out|execute|obey|"
     r"follow (it|them|the)|do (it|what it says|as it says)|act on it|run it|apply it)\b"),
    # authority claims: someone asserting a role the model should defer to
    ("authority_claim",
     r"\b(admin(istrator)?|system|developer|root|security team|ops team)\s+(override|mode (enabled|on)|access granted)\b"
     r"|\byou (may|can|are (now )?allowed to|are now permitted to) now\b"
     r"|\byou (may|can) now (share|reveal|disclose|ignore|bypass|send)\b"),
]]
_WEIGHTS.update({n: w for n, w, _ in _TRIPWIRE_RULES})
_CATEGORY_TW = {"deferred_execution": "injection", "authority_claim": "injection"}


def scan_text(text: str, threshold: float = 1.0, extra_phrases: list[str] = (),
              rule_weights: dict[str, float] | None = None) -> dict[str, list[str]]:
    """Categories found in a piece of untrusted text, with the rule names behind each.
    rule_weights overrides Bastion's default weight for a rule (set by the closed loop after review)."""
    out: dict[str, list[str]] = {}
    plain = normalise(text)
    hits = scan_injection(text).rules + [n for n, _, rx in _TRIPWIRE_RULES if rx.search(plain)]
    w = {**_WEIGHTS, **(rule_weights or {})}
    low = plain.lower()
    extra = [p for p in extra_phrases if p.lower() in low]
    if sum(w[h] for h in hits) >= threshold or extra:
        for rule in hits:
            out.setdefault(_CATEGORY.get(rule) or _CATEGORY_TW.get(rule, "injection"), []).append(rule)
        if extra:
            out.setdefault("injection", []).extend(f"phrase:{p}" for p in extra)
    secrets = [n for n, rx in _SECRETS if rx.search(text)]
    if secrets:
        out["secrets"] = secrets
    if _OVERLOAD.search(text):
        out.setdefault("overload", []).append("overload_pattern")
    words = low.split()
    if len(words) > 400 and len(set(words)) / len(words) < 0.05:
        out.setdefault("overload", []).append("token_flood")
    return out


def scan_output(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    if _EXFIL.search(text):
        out["output_exfil"] = ["exfil_url"]
    secrets = [n for n, rx in _SECRETS if rx.search(text)]
    if secrets:
        out["secrets"] = secrets
    return out


__all__ = ["approx_tokens", "scan_text", "scan_output", "find_pii", "redact_pii"]
