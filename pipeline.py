"""The Secure Gateway pipeline: validate -> policy -> LLM sandbox -> output filter -> audit."""
from __future__ import annotations

import hashlib
import time

from fastapi import HTTPException

from .context import Ctx
from .deps import Principal
from .llm_client import LLMError
from .policy import SEV_ORDER, scan_input, scan_output, should_block

WITHHELD = "[withheld by output policy]"
BLOCKED = "[blocked by gateway policy]"


def _top_severity(violations: list[dict]) -> str:
    return max((v["severity"] for v in violations), key=lambda s: SEV_ORDER[s], default="info")


def run_prompt(ctx: Ctx, who: Principal, prompt: str, mode: str, attack_id: str | None = None) -> dict:
    t0 = time.perf_counter()
    ctx.detector.on_probe(who.username, who.role, who.ip)
    base = {"prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(), "preview": prompt[:200],
            "mode": mode, "attack_id": attack_id}

    if len(prompt) > ctx.settings.max_prompt_chars:
        ctx.audit.append(actor=who.username, role=who.role, event_type="llm.rejected", severity="low",
                         source_ip=who.ip, details={**base, "reason": "prompt_too_large", "chars": len(prompt)})
        raise HTTPException(413, f"Prompt exceeds {ctx.settings.max_prompt_chars} characters")

    violations = scan_input(prompt, ctx.load_policies())
    ids = [v["id"] for v in violations]
    ctx.audit.append(actor=who.username, role=who.role, event_type="llm.request",
                     severity=_top_severity(violations), source_ip=who.ip,
                     details={**base, "violations": ids})
    if violations:
        ctx.detector.on_violation(who.username, who.role, who.ip, ids)

    blocker = should_block(violations) if mode == "enforce" else None
    if blocker:
        ctx.audit.append(actor=who.username, role=who.role, event_type="llm.blocked", severity="high",
                         source_ip=who.ip, details={"attack_id": attack_id, "rule": blocker, "all_rules": ids})
        return {"blocked": True, "blocked_by": blocker, "violations": ids, "response": BLOCKED,
                "leaked": False, "unsafe": False, "latency_ms": round((time.perf_counter() - t0) * 1000, 2)}

    try:
        raw = ctx.llm.complete(prompt)
    except LLMError as e:
        ctx.audit.append(actor=who.username, role=who.role, event_type="llm.error", severity="medium",
                         source_ip=who.ip, details={"attack_id": attack_id, "reason": str(e)})
        ctx.detector.on_llm_failure(who.username, who.role, who.ip, str(e))
        raise HTTPException(502, "LLM sandbox unavailable")

    out = scan_output(raw, ctx.settings.canary)
    response = out["redacted"]
    if mode == "enforce" and out["unsafe"]:
        response = WITHHELD
    if out["leaked"]:
        ctx.audit.append(actor=who.username, role=who.role, event_type="llm.leak_detected", severity="critical",
                         source_ip=who.ip, details={"attack_id": attack_id, "mode": mode})
        ctx.detector.on_leak(who.username, who.role, who.ip, attack_id)
    ctx.audit.append(actor=who.username, role=who.role, event_type="llm.response", severity="info",
                     source_ip=who.ip, details={"attack_id": attack_id, "leaked": out["leaked"],
                                                "unsafe": out["unsafe"], "preview": response[:200]})
    return {"blocked": False, "blocked_by": None, "violations": ids, "response": response,
            "leaked": out["leaked"], "unsafe": out["unsafe"],
            "latency_ms": round((time.perf_counter() - t0) * 1000, 2)}
