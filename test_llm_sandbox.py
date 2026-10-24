import json
import time
import uuid

from fastapi.testclient import TestClient


def signed(env, body: dict, ts=None, rid=None, secret=None):
    from bayora_gateway.security import sign_service_request
    raw = json.dumps(body).encode()
    rid, ts = rid or uuid.uuid4().hex, ts or str(int(time.time()))
    sig = sign_service_request(secret or env.service_secret, rid, ts, raw)
    return raw, {"Content-Type": "application/json", "X-Bayora-Request-Id": rid,
                 "X-Bayora-Timestamp": ts, "X-Bayora-Signature": sig}


def test_unsigned_request_forbidden(llm_app):
    c = TestClient(llm_app)
    assert c.post("/v1/complete", json={"prompt": "hi"}).status_code == 403


def test_valid_signature_ok_and_replay_rejected(llm_app, env):
    c = TestClient(llm_app)
    raw, h = signed(env, {"prompt": "hello"})
    assert c.post("/v1/complete", content=raw, headers=h).status_code == 200
    assert c.post("/v1/complete", content=raw, headers=h).status_code == 403


def test_wrong_secret_and_stale_and_tampered_body(llm_app, env):
    c = TestClient(llm_app)
    raw, h = signed(env, {"prompt": "x"}, secret="attacker-secret-attacker-secret")
    assert c.post("/v1/complete", content=raw, headers=h).status_code == 403
    raw, h = signed(env, {"prompt": "x"}, ts=str(int(time.time()) - 600))
    assert c.post("/v1/complete", content=raw, headers=h).status_code == 403
    raw, h = signed(env, {"prompt": "x"})
    assert c.post("/v1/complete", content=json.dumps({"prompt": "y"}).encode(), headers=h).status_code == 403


def test_production_refuses_weak_secrets(monkeypatch):
    import pytest
    from bayora_gateway.config import ConfigError, get_settings
    monkeypatch.setenv("BAYORA_ENV", "production")
    monkeypatch.setenv("JWT_SECRET", "change-me")
    get_settings.cache_clear()
    with pytest.raises(ConfigError):
        get_settings()
    get_settings.cache_clear()
