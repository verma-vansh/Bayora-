"""Password hashing, JWTs and HMAC service-to-service request signing."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
import uuid

import jwt

ISSUER = "bayora-gateway"
AUDIENCE = "bayora"


def hash_password(password: str, n: int = 2**14, r: int = 8, p: int = 1) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    b = lambda x: base64.b64encode(x).decode()  # noqa: E731
    return f"scrypt${n}${r}${p}${b(salt)}${b(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, dk = stored.split("$")
        calc = hashlib.scrypt(
            password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=32
        )
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except Exception:
        return False


def create_token(secret: str, username: str, role: str, ttl_minutes: int) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "sub": username, "role": role, "iat": now, "exp": now + ttl_minutes * 60,
            "iss": ISSUER, "aud": AUDIENCE, "jti": uuid.uuid4().hex,
        },
        secret,
        algorithm="HS256",
    )


def decode_token(secret: str, token: str) -> dict:
    return jwt.decode(
        token, secret, algorithms=["HS256"], audience=AUDIENCE, issuer=ISSUER,
        options={"require": ["exp", "iat", "sub", "role", "jti"]},
    )


def sign_service_request(secret: str, request_id: str, ts: str, body: bytes) -> str:
    """HMAC over timestamp, request id and body hash. Verified by the LLM sandbox."""
    msg = f"{ts}.{request_id}.{hashlib.sha256(body).hexdigest()}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()
