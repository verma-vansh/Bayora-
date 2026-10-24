"""Anomaly detection. Alerts are written to the tamper-evident audit log."""
from __future__ import annotations

import time
from collections import defaultdict, deque


class Detector:
    WINDOW = 60.0
    COOLDOWN = 60.0

    def __init__(self, audit, settings, clock=time.monotonic):
        self.audit, self.s, self.clock = audit, settings, clock
        self._events: dict[tuple, deque] = defaultdict(deque)
        self._cool: dict[tuple, float] = {}

    def _count(self, key: tuple) -> int:
        now, q = self.clock(), self._events[key]
        q.append(now)
        while q and now - q[0] > self.WINDOW:
            q.popleft()
        return len(q)

    def alert(self, rule: str, actor: str, role: str, severity: str, ip: str, details: dict) -> bool:
        key, now = (actor, rule), self.clock()
        if now - self._cool.get(key, -1e9) < self.COOLDOWN:
            return False
        self._cool[key] = now
        self.audit.append(actor=actor, role=role, event_type=f"alert.{rule}", severity=severity,
                          source_ip=ip, details=details)
        return True

    # --- hooks -----------------------------------------------------------------
    def on_probe(self, actor, role, ip):
        n = self._count((actor, "probe"))
        if n > self.s.burst_threshold:
            self.alert("rate_burst", actor, role, "medium", ip, {"requests_per_minute": n})

    def on_violation(self, actor, role, ip, violation_ids):
        n = self._count((actor, "violation"))
        if n >= self.s.violation_threshold:
            self.alert("sustained_attack_pattern", actor, role, "high", ip,
                       {"violations_last_minute": n, "latest_rules": violation_ids})

    def on_denied(self, actor, role, ip, path, capability):
        """An authenticated principal reached for a capability outside its zone."""
        self.alert("cross_boundary_access", actor, role, "high", ip,
                   {"path": path, "missing_capability": capability})

    def on_auth_failure(self, ip, username):
        n = self._count((ip, "authfail"))
        if n >= self.s.login_max_failures:
            self.alert("credential_stuffing", ip or "unknown", "anon", "high", ip,
                       {"failures_last_minute": n, "last_username": username[:64]})

    def on_leak(self, actor, role, ip, attack_id):
        self.alert("canary_leak", actor, role, "critical", ip, {"attack_id": attack_id})

    def on_llm_failure(self, actor, role, ip, reason):
        self.alert("llm_sandbox_failure", actor, role, "medium", ip, {"reason": reason})
