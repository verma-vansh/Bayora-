from sqlalchemy import text


def _engine(app):
    return app.state.ctx.sf.kw["bind"]


def test_chain_valid_and_growing(app):
    a = app.state.ctx.audit
    for i in range(5):
        a.append(actor="t", role="red", event_type="x", details={"i": i})
    v = a.verify()
    assert v["valid"] and v["events"] >= 6 and len(v["head_hash"]) == 64


def test_modified_content_detected(app):
    a = app.state.ctx.audit
    for i in range(4):
        a.append(actor="t", role="red", event_type="x", details={"i": i})
    with _engine(app).begin() as c:
        c.execute(text("UPDATE audit_events SET actor='mallory' WHERE seq=3"))
    v = a.verify()
    assert not v["valid"] and v["first_invalid_seq"] == 3 and v["reason"] == "content_modified"


def test_deleted_row_detected(app):
    a = app.state.ctx.audit
    for i in range(4):
        a.append(actor="t", role="red", event_type="x", details={"i": i})
    with _engine(app).begin() as c:
        c.execute(text("DELETE FROM audit_events WHERE seq=3"))
    v = a.verify()
    assert not v["valid"] and v["reason"] == "sequence_gap"


def test_forged_hash_without_key_detected(app):
    """Attacker recomputes the SHA-256 chain but lacks the HMAC key."""
    import hashlib
    from bayora_gateway.audit import _canonical, _chain_hash
    a = app.state.ctx.audit
    a.append(actor="t", role="red", event_type="x", details={})
    with _engine(app).begin() as c:
        row = c.execute(text("SELECT seq,ts,role,event_type,severity,source_ip,prev_hash FROM audit_events WHERE seq=2")).one()
        h = _chain_hash(row.prev_hash, _canonical(2, row.ts, "forger", row.role, row.event_type,
                                                  row.severity, row.source_ip, "{}"))
        c.execute(text("UPDATE audit_events SET actor='forger', hash=:h WHERE seq=2"), {"h": h})
    v = a.verify()
    assert not v["valid"] and v["reason"] in ("signature_invalid", "chain_break")


def test_concurrent_appends_keep_chain(app):
    from concurrent.futures import ThreadPoolExecutor
    a = app.state.ctx.audit
    with ThreadPoolExecutor(8) as ex:
        list(ex.map(lambda i: a.append(actor="t", role="red", event_type="x", details={"i": i}), range(40)))
    assert a.verify()["valid"]
