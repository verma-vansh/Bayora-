"""Verifies HMAC-signed requests from the gateway; rejects stale and replayed ones."""
import hashlib
import hmac
import threading
import time

MAX_SKEW = 30


def sign(secret: str, request_id: str, ts: str, body: bytes) -> str:
    msg = f"{ts}.{request_id}.{hashlib.sha256(body).hexdigest()}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


class Verifier:
    def __init__(self, secret: str):
        self.secret, self._seen, self._lock = secret, {}, threading.Lock()

    def check(self, request_id: str, ts: str, signature: str, body: bytes) -> str | None:
        """Return None if valid, else a short failure reason."""
        try:
            skew = abs(time.time() - int(ts))
        except ValueError:
            return "bad_timestamp"
        if skew > MAX_SKEW:
            return "stale_timestamp"
        if not hmac.compare_digest(sign(self.secret, request_id, ts, body), signature or ""):
            return "bad_signature"
        with self._lock:
            now = time.time()
            self._seen = {k: v for k, v in self._seen.items() if now - v < MAX_SKEW * 2}
            if request_id in self._seen:
                return "replay"
            self._seen[request_id] = now
        return None
