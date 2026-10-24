# Bayora - Secure AI Testing Platform

> **"Attack the AI without exposing the attack."**
> Hack in Hills - Problem Statement #04 - Team **MounTechies**

![CI](https://github.com/verma-vansh/bayora/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue)

Red teams, blue teams and client LLMs usually share one environment, so attack payloads, defensive logic and model state can leak between them. **Bayora** is a zone-isolated platform for adversarial LLM testing: every prompt passes a **Secure Gateway**, the model lives in a network-isolated sandbox, and every event lands in a **tamper-evident audit chain** the blue team can verify at any time.

| Problem | Bayora control |
|---|---|
| Cross-team information leakage | Capability-based RBAC; red never learns *which* rule blocked it; blue policies are invisible to red |
| Side channels / secret exfiltration | Canary detection catches plain, reversed, spaced and base64 leaks; output is always redacted |
| Model contamination / direct access | Model on an internal-only network; gateway-signed (HMAC, 30 s, replay-proof) requests only |
| Untrustworthy audit trails | SHA-256 chain + HMAC; Postgres role that **cannot** UPDATE/DELETE; one-click verify |
| Slow detection | Anomaly rules -> alerts in the audit chain -> JSON-lines stream for any SIEM |

## Results (built-in 30-prompt suite, mock target model)

| Mode | Attack success | Risk score | False positives |
|---|---|---|---|
| Raw model (`monitor`, gateway only logs) | **70.8 %** | **81.5 / 100** | 0 % |
| Through Bayora (`enforce`) | **0 %** | **0 / 100** | **0 %** |

`enforce` outcome mix: 17 blocked, 6 resisted, 1 contained, 6 benign passed. Numbers come from the mock model (see limits below); use `LLM_BACKEND=openai` for a real model.

## Quick start

```bash
git clone https://github.com/verma-vansh/bayora && cd bayora
./scripts/gen_env.sh            # strong random secrets -> .env (prints the 3 logins)
docker compose up --build -d    # dashboard: http://localhost:8080   API docs are disabled in production
docker compose --profile tools run --rm red-runner --mode enforce   # automated campaign
docker compose --profile monitor up blue-agent                       # SIEM-style JSON stream
./scripts/verify_isolation.sh   # proves red cannot reach LLM / DB / internet
```

No Docker? Dev mode runs on SQLite with built-in dev credentials (`dev-red_operator-pass-123`, ...):

```bash
python -m venv .venv && . .venv/bin/activate && pip install -r gateway/requirements-dev.txt
make test
(cd llm-sandbox && SERVICE_SECRET=dev-only-service-secret-0123456789abcdef CANARY_SECRET='BAYORA{dev-only-canary-0f1e2d3c4b5a}' uvicorn bayora_llm.main:app --port 9000 &)
(cd gateway && LLM_URL=http://127.0.0.1:9000 uvicorn --factory bayora_gateway.main:create_app --port 8000 &)
(cd dashboard && npm install && npm run dev)     # http://localhost:5173
```

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (diagram + slide-to-code mapping) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

```
red_net ── red-runner ─┐                    ┌── llm_net ── llm-sandbox (no internet)
edge ───── dashboard ──┼──►  GATEWAY  ◄─────┤
blue_net ─ blue-agent ─┘  (auth·policy·      └── data_net ── PostgreSQL (append-only audit)
                           sign·filter·audit)
```

## API

| Endpoint | Role | Purpose |
|---|---|---|
| `POST /auth/login`, `GET /me` | all | JWT login (lockout after repeated failures) |
| `POST /red/probe` | red | One prompt through the gateway (`enforce` / `monitor`) |
| `POST /red/campaigns`, `GET /red/campaigns[/id]` | red | Run / read own attack campaigns (rule ids hidden) |
| `GET /red/attacks` | red | Attack library |
| `GET /blue/stats`, `/blue/audit`, `/blue/alerts` | blue | Metrics, full event log, alerts |
| `GET /blue/audit/verify` | blue | Recompute the hash chain; first bad event + `head_hash` |
| `GET/POST/DELETE /blue/policies`, `GET /blue/rules` | blue | Live custom block/flag rules |
| `GET /blue/campaigns[/id]` | blue | All campaigns with per-rule detail |

`admin` has both capability sets. Interactive docs at `/docs` outside production.

## Verification status (be honest with judges)

| Area | Status |
|---|---|
| 35 pytest tests (audit tampering, RBAC, signing/replay, policy, pipeline, campaigns) | passing |
| Live run: gateway + sandbox as separate processes, red-runner, blue-agent, tamper detection | executed and verified |
| Dashboard `vite build` | passing |
| `docker compose` stack, Postgres init script, `verify_isolation.sh` | written, **not yet executed** (no Docker where this was authored) - CI runs `compose config` + `build`; run `docker compose up` once before demoing |
| OpenAI backend | implemented, needs your API key; untested against the live API |

## Limitations & roadmap

Documented in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): external anchoring of audit head hash, KMS-held audit key, Redis-backed detector for HA, gVisor/Kata sandboxes, TLS ingress, mobile app, enterprise SSO/SIEM connectors (the future scope from the pitch deck).

## Team MounTechies

Vansh Verma - Cybersecurity & Infrastructure - Diwakar Kumar - AI / Red-Team & Testing - Stuti Pandey - Backend, Dashboard & Documentation

MIT licensed. Authorised security testing only.
