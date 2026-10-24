#!/usr/bin/env python3
"""Blue-team monitoring agent. Lives on blue_net: polls the gateway, verifies the audit chain,
and emits JSON lines (stdout) that Grafana Loki / any SIEM can ingest. Optional webhook forwarding."""
import json
import os
import sys
import time

import httpx

GATEWAY = os.environ.get("GATEWAY_URL", "http://gateway:8000")
INTERVAL = int(os.environ.get("POLL_SECONDS", "15"))
WEBHOOK = os.environ.get("SIEM_WEBHOOK_URL", "")


def emit(kind: str, payload: dict, hook: httpx.Client):
    line = {"source": "bayora-blue-agent", "kind": kind, **payload}
    print(json.dumps(line, separators=(",", ":")), flush=True)
    if WEBHOOK:
        try:
            hook.post(WEBHOOK, json=line, timeout=5)
        except httpx.HTTPError as e:
            print(json.dumps({"kind": "webhook_error", "error": type(e).__name__}), flush=True)


def login(c: httpx.Client) -> dict:
    r = c.post("/auth/login", json={"username": os.environ.get("BLUE_USER", "blue_analyst"),
                                    "password": os.environ.get("BLUE_PASSWORD", "")})
    r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def main():
    last_seq, headers = 0, None
    with httpx.Client(base_url=GATEWAY, timeout=15) as c, httpx.Client() as hook:
        while True:
            try:
                headers = headers or login(c)
                v = c.get("/blue/audit/verify", headers=headers)
                if v.status_code == 401:
                    headers = None
                    continue
                v = v.json()
                emit("audit_integrity", v, hook)
                if not v["valid"]:
                    emit("CRITICAL_TAMPERING", {"first_invalid_seq": v["first_invalid_seq"], "reason": v["reason"]}, hook)
                alerts = c.get("/blue/alerts", headers=headers, params={"since_seq": last_seq, "limit": 200}).json()
                for a in sorted(alerts, key=lambda x: x["seq"]):
                    emit("alert", a, hook)
                    last_seq = max(last_seq, a["seq"])
            except (httpx.HTTPError, ValueError) as e:
                print(json.dumps({"kind": "agent_error", "error": type(e).__name__}), flush=True)
                headers = None
            time.sleep(INTERVAL)


if __name__ == "__main__":
    sys.exit(main())
