import random
import string
import time

import pytest
from fastapi.testclient import TestClient

from manager.api.main import create_app

ADMIN = {"X-Admin-Key": "test-admin-key"}
rng = random.Random(9)


def rand(n):
    return "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))


@pytest.fixture
def client(tmp_path):
    app = create_app(str(tmp_path / "api.db"), scheduler=False, admin_key="test-admin-key")
    with TestClient(app) as c:
        yield c


def make_agent(client, name="pc1"):
    r = client.post("/api/v1/admin/agents", json={"name": name, "os": "linux"}, headers=ADMIN)
    assert r.status_code == 201
    return {"X-API-Key": r.json()["api_key"]}


def tunnel_batch(batch_id="b1", n=280, parent="evil-dns.xyz"):
    now = time.time()
    return {"batch_id": batch_id, "os": "linux", "agent_version": "0.1",
            "queries": [{"ts": now - 290 + i, "qname": f"{rand(30)}.{rand(18)}.c2.{parent}", "qtype": "TXT"}
                        for i in range(n)]}


# ---- auth ----
def test_health_is_open(client):
    assert client.get("/api/v1/health").json()["status"] == "ok"


def test_admin_endpoints_need_admin_key(client):
    assert client.get("/api/v1/admin/agents").status_code == 401
    assert client.get("/api/v1/admin/agents", headers={"X-Admin-Key": "nope"}).status_code == 401
    assert client.get("/api/v1/alerts").status_code == 401
    assert client.get("/api/v1/stats").status_code == 401


def test_agent_endpoints_need_agent_key(client):
    assert client.post("/api/v1/agent/ingest", json=tunnel_batch()).status_code == 401
    bad = {"X-API-Key": "dh_agent_fake"}
    assert client.post("/api/v1/agent/ingest", json=tunnel_batch(), headers=bad).status_code == 401
    # an agent key must not open admin endpoints
    h = make_agent(client)
    assert client.get("/api/v1/admin/agents", headers=h).status_code == 401


def test_disabled_agent_is_rejected(client):
    h = make_agent(client)
    client.patch("/api/v1/admin/agents/1", json={"enabled": False}, headers=ADMIN)
    assert client.post("/api/v1/agent/ingest", json=tunnel_batch(), headers=h).status_code == 403


def test_rotate_key(client):
    h = make_agent(client)
    new = client.post("/api/v1/admin/agents/1/rotate-key", headers=ADMIN).json()["api_key"]
    assert client.get("/api/v1/agent/config", headers=h).status_code == 401
    assert client.get("/api/v1/agent/config", headers={"X-API-Key": new}).status_code == 200


def test_duplicate_agent_name_409(client):
    make_agent(client)
    r = client.post("/api/v1/admin/agents", json={"name": "pc1"}, headers=ADMIN)
    assert r.status_code == 409


def test_bad_agent_name_422(client):
    assert client.post("/api/v1/admin/agents", json={"name": "bad name!"}, headers=ADMIN).status_code == 422


# ---- ingest ----
def test_ingest_and_dedupe(client):
    h = make_agent(client)
    r = client.post("/api/v1/agent/ingest", json=tunnel_batch("b1"), headers=h).json()
    assert r == {"accepted": 280, "dropped": 0, "ignored_trusted": 0, "duplicate": False, "blocks_rev": 0}
    again = client.post("/api/v1/agent/ingest", json=tunnel_batch("b1"), headers=h).json()
    assert again["duplicate"] is True and again["accepted"] == 0
    agents = client.get("/api/v1/admin/agents", headers=ADMIN).json()
    assert agents[0]["total_queries"] == 280 and agents[0]["online"] is True and agents[0]["os"] == "linux"


def test_ingest_drops_bad_rows_and_ignores_trusted(client):
    h = make_agent(client)
    client.patch("/api/v1/admin/settings", json={"config": {"trusted_domains": ["google.com"]}}, headers=ADMIN)
    now = time.time()
    body = {"batch_id": "x", "queries": [
        {"ts": now, "qname": "www.google.com", "qtype": "A"},          # trusted
        {"ts": now, "qname": "", "qtype": "A"},                        # empty
        {"ts": now + 99999, "qname": "a.evil.com", "qtype": "A"},      # future
        {"ts": now - 99 * 86400, "qname": "a.evil.com", "qtype": "A"}, # too old
        {"ts": now, "qname": "a" * 300 + ".com", "qtype": "A"},        # too long
        {"ts": now, "qname": "ok.evil.com", "qtype": "txt"},           # good
    ]}
    r = client.post("/api/v1/agent/ingest", json=body, headers=h).json()
    assert r["accepted"] == 1 and r["dropped"] == 4 and r["ignored_trusted"] == 1


def test_batch_too_large_413(client):
    h = make_agent(client)
    client.patch("/api/v1/admin/settings", json={"config": {"agent": {"max_batch_size": 10}}}, headers=ADMIN)
    assert client.post("/api/v1/agent/ingest", json=tunnel_batch(n=11), headers=h).status_code == 413


def test_rate_limit_429(client):
    h = make_agent(client)
    client.patch("/api/v1/admin/settings", json={"config": {"agent": {"max_batches_per_minute": 2}}}, headers=ADMIN)
    codes = [client.post("/api/v1/agent/ingest", json=tunnel_batch(f"r{i}", n=1), headers=h).status_code
             for i in range(3)]
    assert codes == [200, 200, 429]


def test_malformed_body_422(client):
    h = make_agent(client)
    assert client.post("/api/v1/agent/ingest", json={"queries": []}, headers=h).status_code == 422


def test_heartbeat_and_config(client):
    h = make_agent(client)
    r = client.post("/api/v1/agent/heartbeat", json={"os": "windows", "agent_version": "0.2"}, headers=h).json()
    assert r["ok"] and r["config"]["batch_interval_seconds"] == 10
    assert client.get("/api/v1/admin/agents", headers=ADMIN).json()[0]["os"] == "windows"
    assert "trusted_domains" in client.get("/api/v1/agent/config", headers=h).json()


# ---- end to end: ingest -> engine -> alerts ----
def test_end_to_end_alert_flow(client):
    h = make_agent(client)
    client.post("/api/v1/agent/ingest", json=tunnel_batch(), headers=h)

    run = client.post("/api/v1/admin/run/fast", headers=ADMIN).json()
    assert run["created"] == 1

    data = client.get("/api/v1/alerts", headers=ADMIN).json()
    assert data["total"] == 1
    a = data["items"][0]
    assert a["severity"] == "high" and a["host"] == "pc1" and a["parent"] == "evil-dns.xyz"
    assert len(a["signals"]) == 7 and a["signals"][0]["points"] >= a["signals"][-1]["points"]

    assert client.get(f"/api/v1/alerts/{a['id']}", headers=ADMIN).json()["id"] == a["id"]
    assert client.get("/api/v1/alerts?severity=low", headers=ADMIN).json()["total"] == 0
    assert client.get("/api/v1/alerts?status=bogus", headers=ADMIN).status_code == 422

    s = client.get("/api/v1/stats", headers=ADMIN).json()
    assert s["alerts_open"]["high"] == 1 and s["agents"]["online"] == 1 and s["queries_last_hour"] == 280


def test_ack_and_false_positive_suppression(client):
    h = make_agent(client)
    client.post("/api/v1/agent/ingest", json=tunnel_batch(), headers=h)
    client.post("/api/v1/admin/run/fast", headers=ADMIN)
    aid = client.get("/api/v1/alerts", headers=ADMIN).json()["items"][0]["id"]

    assert client.patch(f"/api/v1/alerts/{aid}", json={"status": "ack"}, headers=ADMIN).status_code == 200
    assert client.get(f"/api/v1/alerts/{aid}", headers=ADMIN).json()["status"] == "ack"

    client.patch(f"/api/v1/alerts/{aid}", json={"status": "false_positive"}, headers=ADMIN)
    run = client.post("/api/v1/admin/run/fast", headers=ADMIN).json()
    assert run["suppressed"] == 1 and run["created"] == 0
    assert client.patch("/api/v1/alerts/999", json={"status": "ack"}, headers=ADMIN).status_code == 404
    assert client.patch(f"/api/v1/alerts/{aid}", json={"status": "expired"}, headers=ADMIN).status_code == 422


def test_trust_domain_button(client):
    h = make_agent(client)
    client.post("/api/v1/agent/ingest", json=tunnel_batch(), headers=h)
    client.post("/api/v1/admin/run/fast", headers=ADMIN)
    aid = client.get("/api/v1/alerts", headers=ADMIN).json()["items"][0]["id"]

    r = client.post(f"/api/v1/alerts/{aid}/trust-domain", headers=ADMIN).json()
    assert r["trusted"] == "evil-dns.xyz" and r["alerts_closed"] == 1
    assert "evil-dns.xyz" in client.get("/api/v1/admin/settings", headers=ADMIN).json()["trusted_domains"]
    # engine now skips it
    assert client.post("/api/v1/admin/run/fast", headers=ADMIN).json()["created"] == 0
    # new queries for it are ignored at ingest
    r = client.post("/api/v1/agent/ingest", json=tunnel_batch("b2", n=5), headers=h).json()
    assert r["ignored_trusted"] == 5


def test_campaign_endpoint(client):
    h1, h2 = make_agent(client, "pc1"), make_agent(client, "pc2")
    client.post("/api/v1/agent/ingest", json=tunnel_batch("a"), headers=h1)
    client.post("/api/v1/agent/ingest", json=tunnel_batch("a"), headers=h2)
    client.post("/api/v1/admin/run/fast", headers=ADMIN)
    c = client.get("/api/v1/campaigns", headers=ADMIN).json()
    assert len(c) == 1 and c[0]["parent"] == "evil-dns.xyz" and sorted(c[0]["host_list"]) == ["pc1", "pc2"]


def test_run_unknown_profile_404(client):
    assert client.post("/api/v1/admin/run/nope", headers=ADMIN).status_code == 404


# ---- settings ----
def test_settings_defaults_and_patch(client):
    s = client.get("/api/v1/admin/settings", headers=ADMIN).json()
    assert set(s["profiles"]) == {"fast", "slow"}
    r = client.patch("/api/v1/admin/settings", headers=ADMIN, json={"config": {
        "profiles": {"slow": {"window_seconds": 43200, "weights": {"entropy": 0.4}}}}})
    assert r.status_code == 200
    again = client.get("/api/v1/admin/settings", headers=ADMIN).json()
    assert again["profiles"]["slow"]["window_seconds"] == 43200
    assert again["profiles"]["slow"]["weights"]["entropy"] == 0.4
    assert again["profiles"]["slow"]["weights"]["depth"] == 0.10      # untouched
    assert again["profiles"]["fast"]["window_seconds"] == 300         # untouched


def test_settings_validation_422(client):
    r = client.patch("/api/v1/admin/settings", headers=ADMIN,
                     json={"config": {"profiles": {"fast": {"weights": {"entropy": -5}}}}})
    assert r.status_code == 422 and r.json()["detail"]["errors"]
    # nothing was saved
    assert client.get("/api/v1/admin/settings", headers=ADMIN).json()["profiles"]["fast"]["weights"]["entropy"] == 0.20


def test_settings_put_and_reset(client):
    client.put("/api/v1/admin/settings", headers=ADMIN, json={"config": {"retention_days": 30}})
    assert client.get("/api/v1/admin/settings", headers=ADMIN).json()["retention_days"] == 30
    r = client.post("/api/v1/admin/settings/reset", headers=ADMIN).json()
    assert r["retention_days"] == 7
    assert client.get("/api/v1/admin/settings", headers=ADMIN).json()["retention_days"] == 7


def test_settings_persist_across_restart(tmp_path):
    path = str(tmp_path / "p.db")
    with TestClient(create_app(path, scheduler=False, admin_key="k")) as c:
        c.patch("/api/v1/admin/settings", headers={"X-Admin-Key": "k"},
                json={"config": {"retention_days": 21}})
    with TestClient(create_app(path, scheduler=False, admin_key="k")) as c:
        assert c.get("/api/v1/admin/settings", headers={"X-Admin-Key": "k"}).json()["retention_days"] == 21
