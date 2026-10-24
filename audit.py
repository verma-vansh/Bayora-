"""Tamper-evident audit log.

Every event stores  hash = SHA256(prev_hash || canonical_record)  and
sig = HMAC-SHA256(audit_key, hash).  Editing, deleting or re-ordering any row
breaks the chain; forging a replacement chain additionally requires the HMAC key.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading

from sqlalchemy import select, text

from .db import AuditEvent, now_iso

GENESIS = "0" * 64


def _canonical(seq, ts, actor, role, event_type, severity, source_ip, details: str) -> bytes:
    return json.dumps(
        [seq, ts, actor, role, event_type, severity, source_ip, details],
        separators=(",", ":"), ensure_ascii=True,
    ).encode()


def _chain_hash(prev_hash: str, record: bytes) -> str:
    return hashlib.sha256(prev_hash.encode() + record).hexdigest()


class AuditLog:
    def __init__(self, session_factory, key: str, dialect: str):
        self._sf = session_factory
        self._key = key.encode()
        self._dialect = dialect
        self._lock = threading.Lock()

    def _sign(self, h: str) -> str:
        return hmac.new(self._key, h.encode(), hashlib.sha256).hexdigest()

    def append(self, *, actor: str, role: str, event_type: str, severity: str = "info",
               source_ip: str = "", details: dict | None = None) -> dict:
        details_s = json.dumps(details or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        with self._lock, self._sf() as s, s.begin():
            if self._dialect == "postgresql":
                s.execute(text("SELECT pg_advisory_xact_lock(727274)"))
            last = s.execute(select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(1)).scalar_one_or_none()
            seq = (last.seq + 1) if last else 1
            prev = last.hash if last else GENESIS
            ts = now_iso()
            h = _chain_hash(prev, _canonical(seq, ts, actor, role, event_type, severity, source_ip, details_s))
            s.add(AuditEvent(seq=seq, ts=ts, actor=actor, role=role, event_type=event_type,
                             severity=severity, source_ip=source_ip, details=details_s,
                             prev_hash=prev, hash=h, sig=self._sign(h)))
        return {"seq": seq, "hash": h}

    def verify(self) -> dict:
        prev, expected_seq, count = GENESIS, 1, 0
        with self._sf() as s:
            for ev in s.execute(select(AuditEvent).order_by(AuditEvent.seq)).scalars():
                reason = None
                if ev.seq != expected_seq:
                    reason = "sequence_gap"
                elif ev.prev_hash != prev:
                    reason = "chain_break"
                else:
                    h = _chain_hash(prev, _canonical(ev.seq, ev.ts, ev.actor, ev.role, ev.event_type,
                                                     ev.severity, ev.source_ip, ev.details))
                    if h != ev.hash:
                        reason = "content_modified"
                    elif not hmac.compare_digest(self._sign(h), ev.sig):
                        reason = "signature_invalid"
                if reason:
                    return {"valid": False, "events": count, "first_invalid_seq": ev.seq,
                            "reason": reason, "head_hash": prev}
                prev, expected_seq, count = ev.hash, expected_seq + 1, count + 1
        return {"valid": True, "events": count, "first_invalid_seq": None, "reason": None, "head_hash": prev}

    def list(self, *, limit=100, before_seq=None, event_prefix=None, min_seq=None) -> list[dict]:
        with self._sf() as s:
            q = select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(min(limit, 500))
            if before_seq:
                q = q.where(AuditEvent.seq < before_seq)
            if min_seq:
                q = q.where(AuditEvent.seq > min_seq)
            if event_prefix:
                q = q.where(AuditEvent.event_type.like(event_prefix.replace("%", "") + "%"))
            rows = s.execute(q).scalars().all()
        out = []
        for r in rows:
            try:
                d = json.loads(r.details)
            except ValueError:
                d = {}
            out.append({"seq": r.seq, "ts": r.ts, "actor": r.actor, "role": r.role,
                        "event_type": r.event_type, "severity": r.severity, "source_ip": r.source_ip,
                        "details": d, "hash": r.hash, "prev_hash": r.prev_hash})
        return out

    def counts(self) -> dict:
        from sqlalchemy import func
        with self._sf() as s:
            by_type = dict(s.execute(select(AuditEvent.event_type, func.count()).group_by(AuditEvent.event_type)).all())
            alerts = dict(s.execute(select(AuditEvent.severity, func.count()).where(
                AuditEvent.event_type.like("alert.%")).group_by(AuditEvent.severity)).all())
            total = s.execute(select(func.count()).select_from(AuditEvent)).scalar_one()
        return {"total": total, "by_type": by_type, "alerts_by_severity": alerts}
