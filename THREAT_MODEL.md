# Threat model

| # | Threat (from the problem statement) | Control | Evidence |
|---|---|---|---|
| T1 | Red payloads / blue defences leak across teams | Capability RBAC; red results hide which rule fired; blue policies readable only by blue | `test_rbac.py` |
| T2 | Red bypasses the gateway and hits the model | `llm_net` internal network; HMAC-signed, time-boxed, replay-protected calls | `test_llm_sandbox.py`, `scripts/verify_isolation.sh` |
| T3 | Model secrets exfiltrated (side channel / obfuscated leak) | Output canary detection incl. reversed/spaced/base64; always redacted | `test_policy.py::test_output_redaction_variants`, `test_pipeline.py` |
| T4 | Model contamination by hostile prompts | Prompts never persisted into the model; each call stateless; size limits | design |
| T5 | Audit trail altered after the fact | SHA-256 hash chain + HMAC; Postgres role without UPDATE/DELETE + trigger; `/blue/audit/verify`; blue-agent alerts | `test_audit.py`, live demo `scripts/tamper_demo.py` |
| T6 | Cross-boundary access / probing | Every denial audited and alerted | `test_rbac.py` |
| T7 | Credential attacks | scrypt hashes, constant-time verify, lockout, `alert.credential_stuffing`, JWT alg pinned (`alg:none` rejected) | `test_rbac.py` |
| T8 | ReDoS via blue-supplied regex | Pattern lint (length, nested quantifiers, backrefs) + 4000-char input cap | `test_policy.py::test_regex_safety_lint` |
| T9 | Weak deployment secrets | Production refuses placeholders / short secrets | `test_llm_sandbox.py::test_production_refuses_weak_secrets` |
| T10 | Container breakout / lateral movement | non-root, read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, pids/mem limits | `docker-compose.yml` |

## Known limitations (honest list)

- **Tail truncation**: a hash chain cannot prove the *latest* rows were not deleted. Mitigation: `head_hash` from `/blue/audit/verify` is streamed by the blue agent to an external SIEM; anchor it off-box (roadmap: periodic signed checkpoints / transparency log).
- **Admin of the gateway host** holding `AUDIT_HMAC_KEY` can forge a full chain. Use a KMS/HSM-held key in production.
- **Detector and login throttling state is in-process memory** (single gateway replica). Move to Redis for HA.
- **Isolation is container + network level**, not VM level. For hostile model code use gVisor/Kata/Firecracker (roadmap).
- **No TLS** inside the stack; terminate TLS at a reverse proxy / ingress. Dashboard stores its JWT in `sessionStorage`.
- **Regex/keyword rules are bypassable** by paraphrase (e.g. `PI-A05`). They are one layer; the platform's job is to *measure* that, which the campaign score does.
- The bundled `mock` model is a deterministic simulation, not a real LLM; run `LLM_BACKEND=openai` for real-model numbers.
