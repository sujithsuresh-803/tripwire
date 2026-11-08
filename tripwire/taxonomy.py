"""Every rule category mapped to OWASP Top 10 for LLM Applications 2025, OWASP Top 10 for Agentic
Applications, and MITRE ATLAS, so a SIEM can group detections by threat rather than by tool."""

# category: (OWASP LLM 2025, OWASP Agentic, MITRE ATLAS, severity)
TAXONOMY = {
    "injection":          ("LLM01", "ASI01", "AML.T0051.000", "high"),
    "indirect_injection": ("LLM01", "ASI01", "AML.T0051.001", "high"),
    "rag_poisoning":      ("LLM08", "ASI06", "AML.T0070", "high"),
    "memory_poisoning":   ("LLM04", "ASI06", "", "high"),
    "jailbreak":          ("LLM01", "ASI01", "AML.T0054", "high"),
    "prompt_leak":        ("LLM07", "", "AML.T0056", "medium"),
    "pii":                ("LLM02", "", "AML.T0057", "medium"),
    "secrets":            ("LLM02", "ASI03", "AML.T0057", "high"),
    "output_exfil":       ("LLM05", "ASI02", "AML.T0057", "high"),
    "overload":           ("LLM10", "ASI08", "AML.T0029", "medium"),
    "prompt_budget":      ("LLM10", "ASI08", "AML.T0029", "low"),
    "rate_limit":         ("LLM10", "", "AML.T0034", "low"),
    "tool_not_allowed":   ("LLM06", "ASI02", "", "high"),
    "mcp_server":         ("LLM03", "ASI04", "", "high"),
    "scope":              ("LLM06", "ASI03", "", "high"),
    "tool_args":          ("LLM06", "ASI02", "", "high"),
    "code_exec":          ("LLM06", "ASI05", "", "high"),
    "trifecta":           ("LLM06", "ASI02", "AML.T0057", "high"),
    "quarantined":        ("", "ASI10", "", "high"),
    "kill_switch":        ("", "ASI10", "", "high"),
    "timeout":            ("", "ASI08", "", "low"),
}


def tags(category: str) -> dict:
    owasp, agentic, atlas, sev = TAXONOMY.get(category, ("", "", "", "low"))
    return {"owasp_llm": owasp, "owasp_agentic": agentic, "atlas": atlas, "severity": sev}
