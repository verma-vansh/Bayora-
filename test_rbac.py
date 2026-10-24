def test_unauthenticated_rejected(client):
    assert client.get("/blue/audit").status_code == 401
    assert client.post("/red/probe", json={"prompt": "hi"}).status_code == 401


def test_tampered_and_alg_none_tokens_rejected(client, red):
    tok = red["Authorization"].split()[1]
    bad = tok[:-3] + ("AAA" if not tok.endswith("AAA") else "BBB")
    assert client.get("/me", headers={"Authorization": f"Bearer {bad}"}).status_code == 401
    import base64, json
    h = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    body = tok.split(".")[1]
    assert client.get("/me", headers={"Authorization": f"Bearer {h}.{body}."}).status_code == 401


def test_red_cannot_enter_blue_zone(client, red, blue):
    for path in ["/blue/audit", "/blue/alerts", "/blue/policies", "/blue/stats", "/blue/audit/verify"]:
        assert client.get(path, headers=red).status_code == 403, path
    assert client.post("/blue/policies", headers=red,
                       json={"name": "x", "kind": "keyword", "pattern": "x"}).status_code == 403
    # ...and the attempt is itself an alert visible to blue
    alerts = client.get("/blue/alerts", headers=blue).json()
    assert any(a["event_type"] == "alert.cross_boundary_access" and a["actor"] == "red_operator" for a in alerts)


def test_blue_cannot_attack_llm(client, blue):
    assert client.post("/red/probe", headers=blue, json={"prompt": "hello"}).status_code == 403
    assert client.post("/red/campaigns", headers=blue, json={}).status_code == 403


def test_red_never_sees_defensive_rule_ids(client, red):
    r = client.post("/red/campaigns", headers=red, json={"mode": "enforce"}).json()
    assert all("blocked_by" not in x for x in r["results"])
    assert "PI-001" not in str(r)


def test_red_cannot_read_other_teams_campaigns(client, red, blue):
    cid = client.post("/red/campaigns", headers=red, json={"categories": ["benign"]}).json()["id"]
    assert client.get(f"/blue/campaigns/{cid}", headers=red).status_code == 403
    assert client.get(f"/blue/campaigns/{cid}", headers=blue).status_code == 200


def test_login_lockout_and_audit(client, blue):
    for _ in range(5):
        assert client.post("/auth/login", json={"username": "admin", "password": "wrong-pass"}).status_code == 401
    assert client.post("/auth/login", json={"username": "admin", "password": "wrong-pass"}).status_code == 429
    types = {e["event_type"] for e in client.get("/blue/audit?limit=100", headers=blue).json()}
    assert {"auth.failure", "auth.locked_out"} <= types
