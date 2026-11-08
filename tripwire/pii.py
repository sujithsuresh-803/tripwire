"""PII detection and redaction for Indian and payment identifiers.

Pattern matches are confirmed with the identifier's own checksum where it has one (Verhoeff for Aadhaar,
Luhn for cards), so a random 12-digit claim number is not mistaken for an Aadhaar number.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Verhoeff tables (dihedral group D5)
_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
      [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
      [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
      [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
      [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
      [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]


def verhoeff_ok(digits: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


# (kind, pattern, validator). Earlier kinds win when matches overlap.
_RULES = [
    ("CARD", re.compile(r"\b(?:\d[ -]?){12,18}\d\b"), lambda m: luhn_ok(_digits(m))),
    ("AADHAAR", re.compile(r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b"), lambda m: verhoeff_ok(_digits(m))),
    ("PAN", re.compile(r"\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b"), None),
    ("IFSC", re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"), None),
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), None),
    ("PHONE", re.compile(r"(?<![\w])(?:\+91[ -]?|0)?[6-9]\d{4}[ -]?\d{5}\b"), None),
]


@dataclass
class PiiFinding:
    kind: str
    start: int
    end: int
    value: str


def find_pii(text: str, allow_email_domains: list[str] = ()) -> list[PiiFinding]:
    found: list[PiiFinding] = []
    for kind, rx, valid in _RULES:
        for m in rx.finditer(text):
            if valid and not valid(m.group()):
                continue
            if kind == "EMAIL" and m.group().rsplit("@", 1)[1].lower() in allow_email_domains:
                continue
            if any(f.start < m.end() and m.start() < f.end for f in found):
                continue
            found.append(PiiFinding(kind, m.start(), m.end(), m.group()))
    return sorted(found, key=lambda f: f.start)


def redact_pii(text: str, allow_email_domains: list[str] = ()) -> tuple[str, list[PiiFinding]]:
    findings = find_pii(text, allow_email_domains)
    for f in reversed(findings):
        text = text[:f.start] + f"[{f.kind}]" + text[f.end:]
    return text, findings
