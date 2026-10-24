import os

from fastapi import FastAPI, Header, HTTPException, Request

from . import mock_model, openai_backend
from .auth import Verifier

MAX_BODY = 16 * 1024


def create_app(env: dict | None = None) -> FastAPI:
    e = env or os.environ
    secret = e.get("SERVICE_SECRET", "")
    canary = e.get("CANARY_SECRET", "")
    if len(secret) < 16 or len(canary) < 8:
        raise RuntimeError("SERVICE_SECRET and CANARY_SECRET are required")
    backend = e.get("LLM_BACKEND", "mock")
    verifier = Verifier(secret)
    app = FastAPI(title="Bayora LLM Sandbox", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/health")
    def health():
        return {"status": "ok", "backend": backend}

    @app.post("/v1/complete")
    async def complete(request: Request, x_bayora_request_id: str = Header(""),
                       x_bayora_timestamp: str = Header(""), x_bayora_signature: str = Header("")):
        body = await request.body()
        if len(body) > MAX_BODY:
            raise HTTPException(413, "too large")
        reason = verifier.check(x_bayora_request_id, x_bayora_timestamp, x_bayora_signature, body)
        if reason:
            raise HTTPException(403, "forbidden")
        try:
            prompt = str(__import__("json").loads(body)["prompt"])
        except Exception:
            raise HTTPException(400, "bad request")
        if backend == "openai":
            text = openai_backend.complete(prompt, mock_model.system_prompt(canary),
                                           e["OPENAI_API_KEY"], e.get("OPENAI_MODEL", "gpt-4o-mini"))
        else:
            text = mock_model.respond(prompt, canary)
        return {"text": text, "backend": backend}

    return app


app = None
if os.environ.get("SERVICE_SECRET"):
    app = create_app()
