"""Shared application context (settings, audit log, detector, DB, LLM client)."""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select

from .audit import AuditLog
from .config import Settings
from .db import Policy
from .detection import Detector
from .llm_client import LLMClient


@dataclass
class Ctx:
    settings: Settings
    sf: object
    audit: AuditLog
    detector: Detector
    llm: LLMClient

    def load_policies(self) -> list[Policy]:
        with self.sf() as s:
            return list(s.execute(select(Policy).where(Policy.enabled.is_(True))).scalars())
