"""Input/output policy enforcement for the Secure Gateway."""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"), None)
SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
UNSAFE_MARKER = "[SIMULATED_UNSAFE_COMPLETION]"


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    pattern: re.Pattern
    action: str  # block | flag
    severity: str
    description: str


def _r(i, cat, pat, action, sev, desc):
    return Rule(i, cat, re.compile(pat, re.I | re.S), action, sev, desc)


BUILTIN_RULES = [
    _r("PI-001", "prompt_injection",
       r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|any|your)\b.{0,30}\b(instructions?|rules?|prompts?|guidelines?)\b",
       "block", "high", "Instruction-override phrasing"),
    _r("PI-002", "data_leakage",
       r"\b(reveal|show|print|repeat|display|output|leak|translate|summari[sz]e|rewrite|spell|reverse)\b.{0,40}\b(system|initial|hidden|internal|your|the)?\s*(prompt|instructions|configuration|config|rules)\b",
       "block", "high", "System prompt / configuration extraction"),
    _r("PI-003", "prompt_injection",
       r"(\[system\]|system note:|admin override|<\s*system\s*>)",
       "block", "high", "Fake system/admin channel inside user content"),
    _r("JB-001", "jailbreak",
       r"(do anything now|developer mode|\bDAN mode\b|jailbreak(ed)?\b|without (any )?restrictions)",
       "block", "high", "Known jailbreak persona"),
    _r("JB-002", "jailbreak",
       r"\b(story|fiction|hypothetical(ly)?|role-?play|imagine|pretend)\b.{0,80}\b(bomb|malware|ransomware|weapon|exploit|explosive)\b",
       "block", "medium", "Fictional wrapper around harmful request"),
    _r("DL-001", "data_leakage",
       r"\b(api[\s_-]?key|secret|password|credentials?|canary|private key)\b",
       "flag", "medium", "Secret-seeking vocabulary"),
    _r("ENC-001", "obfuscation", r"[A-Za-z0-9+/]{40,}={0,2}", "flag", "medium", "Long encoded blob"),
]
_DECODED_SCAN = [r for r in BUILTIN_RULES if r.id in {"PI-001", "PI-002", "PI-003", "JB-001"}]
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    return re.sub(r"\s+", " ", text).strip()


def decoded_segments(text: str) -> list[str]:
    out = []
    for m in _B64.findall(text):
        try:
            raw = base64.b64decode(m + "=" * (-len(m) % 4), validate=True)
            s = raw.decode("utf-8")
            if s.isprintable():
                out.append(s)
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
    return out


def is_safe_regex(pattern: str) -> tuple[bool, str]:
    """Blue-team regexes run on every request, so reject catastrophic-backtracking shapes."""
    if len(pattern) > 200:
        return False, "pattern too long (max 200)"
    if re.search(r"\\[1-9]", pattern):
        return False, "backreferences are not allowed"
    if re.search(r"\([^)]*[+*][^)]*\)\s*[+*{]", pattern):
        return False, "nested quantifiers are not allowed"
    if len(re.findall(r"\.[*+]", pattern)) > 2:
        return False, "too many unbounded wildcards"
    try:
        re.compile(pattern)
    except re.error as e:
        return False, f"invalid regex: {e}"
    return True, ""


def scan_input(prompt: str, custom_policies=()) -> list[dict]:
    """Return violations: [{id, category, action, severity, description}]."""
    text = normalize(prompt)
    found: list[dict] = []
    for rule in BUILTIN_RULES:
        if rule.pattern.search(text):
            found.append({"id": rule.id, "category": rule.category, "action": rule.action,
                          "severity": rule.severity, "description": rule.description})
    for seg in decoded_segments(text):
        hit = next((r for r in _DECODED_SCAN if r.pattern.search(normalize(seg))), None)
        if hit:
            found.append({"id": "ENC-002", "category": "obfuscation", "action": "block",
                          "severity": "high", "description": f"Encoded payload hides {hit.id}"})
            break
    low = text.lower()
    for p in custom_policies:
        if not p.enabled:
            continue
        try:
            hit = (p.pattern.lower() in low) if p.kind == "keyword" else bool(re.search(p.pattern, text, re.I))
        except re.error:
            hit = False
        if hit:
            found.append({"id": f"CUS-{p.id}", "category": "custom", "action": p.action,
                          "severity": p.severity, "description": p.name})
    return found


def should_block(violations: list[dict]) -> str | None:
    for v in violations:
        if v["action"] == "block":
            return v["id"]
    return None


def _alnum(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def scan_output(text: str, canary: str) -> dict:
    """Detect canary leakage (plain, reversed, spaced, base64) and unsafe markers; redact."""
    exact = [re.escape(canary), re.escape(canary[::-1]), r"BAYORA\{[^}]*\}", r"sk-[A-Za-z0-9]{20,}"]
    try:
        exact.append(re.escape(base64.b64encode(canary.encode()).decode()))
    except Exception:
        pass
    leaked = False
    redacted = text
    for pat in exact:
        redacted, n = re.subn(pat, "[REDACTED]", redacted)
        leaked = leaked or n > 0
    canon = _alnum(canary)
    fuzzy = canon and (canon in _alnum(redacted) or canon[::-1] in _alnum(redacted))
    if fuzzy:
        leaked = True
        redacted = "[response withheld: sensitive content detected]"
    unsafe = UNSAFE_MARKER in redacted
    return {"leaked": leaked, "unsafe": unsafe, "redacted": redacted}
