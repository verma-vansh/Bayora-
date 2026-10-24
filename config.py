"""Environment-driven settings. Production refuses to start with weak secrets."""
from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

_WEAK_MARKERS = ("change-me", "changeme", "password", "example", "dev-only")


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    env: str
    database_url: str
    jwt_secret: str
    service_secret: str
    audit_key: str
    canary: str
    llm_url: str
    jwt_ttl_minutes: int
    burst_threshold: int
    violation_threshold: int
    max_prompt_chars: int
    login_max_failures: int
    seed_passwords: dict
    cors_origins: tuple


def _secret(name: str, dev_default: str, production: bool, min_len: int = 32) -> str:
    value = os.environ.get(name, "")
    if production:
        if len(value) < min_len or any(m in value.lower() for m in _WEAK_MARKERS):
            raise ConfigError(
                f"{name} must be >= {min_len} chars and not a placeholder in production "
                "(run scripts/gen_env.sh)"
            )
        return value
    return value or dev_default


@lru_cache
def get_settings() -> Settings:
    env = os.environ.get("BAYORA_ENV", "development").lower()
    prod = env == "production"
    seed = {
        "red_operator": ("red", os.environ.get("RED_PASSWORD", "")),
        "blue_analyst": ("blue", os.environ.get("BLUE_PASSWORD", "")),
        "admin": ("admin", os.environ.get("ADMIN_PASSWORD", "")),
    }
    if prod:
        for name, (_, pw) in seed.items():
            if len(pw) < 12 or any(m in pw.lower() for m in _WEAK_MARKERS):
                raise ConfigError(f"password for {name} is weak or unset in production")
    else:
        seed = {k: (r, p or f"dev-{k}-pass-123") for k, (r, p) in seed.items()}
    return Settings(
        env=env,
        database_url=os.environ.get("DATABASE_URL", "sqlite:///./bayora-dev.db"),
        jwt_secret=_secret("JWT_SECRET", "dev-only-jwt-secret-0123456789abcdef0123", prod),
        service_secret=_secret("SERVICE_SECRET", "dev-only-service-secret-0123456789abcdef", prod),
        audit_key=_secret("AUDIT_HMAC_KEY", "dev-only-audit-key-0123456789abcdef0123", prod),
        canary=_secret("CANARY_SECRET", "BAYORA{dev-only-canary-0f1e2d3c4b5a}", prod, 16),
        llm_url=os.environ.get("LLM_URL", "http://llm-sandbox:9000"),
        jwt_ttl_minutes=int(os.environ.get("JWT_TTL_MINUTES", "30")),
        burst_threshold=int(os.environ.get("BURST_THRESHOLD", "120")),
        violation_threshold=int(os.environ.get("VIOLATION_THRESHOLD", "5")),
        max_prompt_chars=int(os.environ.get("MAX_PROMPT_CHARS", "4000")),
        login_max_failures=int(os.environ.get("LOGIN_MAX_FAILURES", "5")),
        seed_passwords={k: v for k, v in seed.items()},
        cors_origins=tuple(o for o in os.environ.get("CORS_ORIGINS", "").split(",") if o),
    )
