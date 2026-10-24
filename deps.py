"""Authentication + capability-based access control (zone isolation for people)."""
from __future__ import annotations

from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, Request

from .context import Ctx
from .security import decode_token

CAPS = {
    "red": frozenset({"llm:probe", "campaign:run", "campaign:read_own"}),
    "blue": frozenset({"audit:read", "audit:verify", "alerts:read", "campaign:read_all",
                       "policy:read", "policy:write", "stats:read"}),
}
CAPS["admin"] = CAPS["red"] | CAPS["blue"]


@dataclass(frozen=True)
class Principal:
    username: str
    role: str
    caps: frozenset
    ip: str


def get_ctx(request: Request) -> Ctx:
    return request.app.state.ctx


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def get_principal(request: Request, ctx: Ctx = Depends(get_ctx)) -> Principal:
    ip = client_ip(request)
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        ctx.audit.append(actor="anonymous", role="anon", event_type="auth.missing_token",
                         severity="low", source_ip=ip, details={"path": request.url.path})
        ctx.detector.on_auth_failure(ip, "")
        raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Bearer"})
    try:
        claims = decode_token(ctx.settings.jwt_secret, token)
    except jwt.PyJWTError as e:
        ctx.audit.append(actor="anonymous", role="anon", event_type="auth.invalid_token",
                         severity="medium", source_ip=ip, details={"path": request.url.path, "error": type(e).__name__})
        ctx.detector.on_auth_failure(ip, "")
        raise HTTPException(401, "Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    role = claims["role"]
    return Principal(claims["sub"], role, CAPS.get(role, frozenset()), ip)


def require(capability: str):
    def dep(request: Request, who: Principal = Depends(get_principal), ctx: Ctx = Depends(get_ctx)) -> Principal:
        if capability not in who.caps:
            ctx.audit.append(actor=who.username, role=who.role, event_type="access.denied", severity="high",
                             source_ip=who.ip, details={"path": request.url.path, "missing_capability": capability})
            ctx.detector.on_denied(who.username, who.role, who.ip, request.url.path, capability)
            raise HTTPException(403, "Forbidden: outside your team's zone")
        return who
    return dep
