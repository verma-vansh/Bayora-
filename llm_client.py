"""Signed client for the isolated LLM sandbox."""
from __future__ import annotations

import json
import time
import uuid

import httpx

from .security import sign_service_request


class LLMError(RuntimeError):
    pass


class LLMClient:
    def __init__(self, base_url: str, secret: str, http: httpx.Client | None = None):
        self.base_url, self.secret = base_url.rstrip("/"), secret
        self.http = http or httpx.Client(timeout=httpx.Timeout(20.0, connect=3.0))

    def complete(self, prompt: str) -> str:
        body = json.dumps({"prompt": prompt}).encode()
        rid, ts = uuid.uuid4().hex, str(int(time.time()))
        headers = {
            "Content-Type": "application/json", "X-Bayora-Request-Id": rid, "X-Bayora-Timestamp": ts,
            "X-Bayora-Signature": sign_service_request(self.secret, rid, ts, body),
        }
        try:
            r = self.http.post(f"{self.base_url}/v1/complete", content=body, headers=headers)
        except httpx.HTTPError as e:
            raise LLMError(f"transport: {type(e).__name__}") from e
        if r.status_code != 200:
            raise LLMError(f"sandbox returned {r.status_code}")
        return str(r.json().get("text", ""))
