import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "llm-sandbox"))
sys.path.insert(0, str(ROOT / "gateway"))


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("BAYORA_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'t.db'}")
    for k in ("JWT_SECRET", "SERVICE_SECRET", "AUDIT_HMAC_KEY", "CANARY_SECRET"):
        monkeypatch.delenv(k, raising=False)
    from bayora_gateway.config import get_settings
    get_settings.cache_clear()
    from bayora_gateway.routes import auth
    auth._failures.clear()
    yield get_settings()
    get_settings.cache_clear()


@pytest.fixture
def llm_app(env):
    from bayora_llm.main import create_app
    return create_app({"SERVICE_SECRET": env.service_secret, "CANARY_SECRET": env.canary})


@pytest.fixture
def app(env, llm_app):
    from bayora_gateway.main import create_app
    return create_app(env, llm_http=TestClient(llm_app, base_url="http://llm-sandbox:9000"))


@pytest.fixture
def client(app):
    return TestClient(app)


def _login(client, user, pw=None):
    r = client.post("/auth/login", json={"username": user, "password": pw or f"dev-{user}-pass-123"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def red(client):
    return _login(client, "red_operator")


@pytest.fixture
def blue(client):
    return _login(client, "blue_analyst")
