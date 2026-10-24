#!/usr/bin/env bash
# Generates a .env with strong random secrets. Never commit the result.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -e .env ] && { echo ".env already exists - refusing to overwrite"; exit 1; }
python3 - <<'PY' > .env
import secrets
r = lambda n=32: secrets.token_urlsafe(n)
print(f"BAYORA_ENV=production")
for k in ("POSTGRES_PASSWORD", "BAYORA_APP_PASSWORD", "JWT_SECRET", "SERVICE_SECRET", "AUDIT_HMAC_KEY"):
    print(f"{k}={r()}")
print(f"CANARY_SECRET=BAYORA{{{secrets.token_hex(12)}}}")
for k in ("RED_PASSWORD", "BLUE_PASSWORD", "ADMIN_PASSWORD"):
    print(f"{k}={r(18)}")
print("LLM_BACKEND=mock\nOPENAI_API_KEY=\nSIEM_WEBHOOK_URL=")
PY
chmod 600 .env
echo "Wrote .env (mode 600). Credentials for the dashboard:"
grep -E '^(RED|BLUE|ADMIN)_PASSWORD' .env
