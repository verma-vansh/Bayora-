"""FastAPI entrypoint."""
from __future__ import annotations

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select

from . import __version__
from .audit import AuditLog
from .config import Settings, get_settings
from .context import Ctx
from .db import User, init_db, make_engine, make_session_factory
from .detection import Detector
from .llm_client import LLMClient
from .routes import auth, blue, red
from .security import hash_password


def create_app(settings: Settings | None = None, llm_http: httpx.Client | None = None) -> FastAPI:
    s = settings or get_settings()
    engine = make_engine(s.database_url)
    init_db(engine)
    sf = make_session_factory(engine)
    audit = AuditLog(sf, s.audit_key, engine.dialect.name)
    ctx = Ctx(s, sf, audit, Detector(audit, s), LLMClient(s.llm_url, s.service_secret, llm_http))

    with sf() as sess, sess.begin():
        for name, (role, pw) in s.seed_passwords.items():
            if not sess.execute(select(User).where(User.username == name)).scalar_one_or_none():
                sess.add(User(username=name, role=role, password_hash=hash_password(pw)))
    audit.append(actor="system", role="system", event_type="system.started", severity="info",
                 details={"version": __version__, "env": s.env})

    app = FastAPI(title="Bayora Secure Gateway", version=__version__,
                  docs_url=None if s.env == "production" else "/docs",
                  redoc_url=None, openapi_url=None if s.env == "production" else "/openapi.json")
    app.state.ctx = ctx
    if s.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=list(s.cors_origins), allow_methods=["GET", "POST", "DELETE"],
                           allow_headers=["Authorization", "Content-Type"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.update({"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
                             "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY"})
        return resp

    @app.exception_handler(Exception)
    async def unhandled(_: Request, exc: Exception):
        return JSONResponse({"detail": "Internal error"}, status_code=500)

    @app.get("/health", tags=["meta"])
    def health():
        return {"status": "ok", "version": __version__}

    app.include_router(auth.router)
    app.include_router(red.router)
    app.include_router(blue.router)
    return app
