import random
import string
import time

import pytest
from fastapi.testclient import TestClient

from manager.api.main import create_app

ADMIN = {"X-Admin-Key": "k"}
rng = random.Random(4)
rand = lambda n: "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(str(tmp_path / "l.db"), scheduler=False, admin_key="k")) as c:
        yield c


def agent(c, name):
    return {"X-API-Key": c.post("/api/v1/admin/agents", json={"name": name}, headers=ADMIN).json()["api_key"]}


def send(c, h, rows, batch="b"):
    return c.post("/api/v1/agent/ingest", json={"batch_id": batch, "queries": rows}, headers=h).json()


def tunnel(n=280, parent="evil-dns.xyz"):
    now = time.time()
    return [{"ts": now - 290 + i, "qname": "%s.%s.c2.%s" % (rand(30), rand(18), parent), "qtype": "TXT",
             "resolver": "8.8.8.8", "proto": "udp", "qbytes": 70, "rbytes": 120, "rcode": 3} for i in range(n)]


# ---------- DNS query log ----------
def test_query_log_filters(client):
    h1, h2 = agent(client, "pc1"), agent(client, "pc2")
    now = time.time()
    send(client, h1, [{"ts": now, "qname": "www.shop.com", "qtype": "A", "rcode": 0},
                      {"ts": now, "qname": "mail.shop.com", "qtype": "MX", "rcode": 3},
                      {"ts": now - 7200, "qname": "old.shop.com", "qtype": "A"}], "a")
    send(client, h2, [{"ts": now, "qname": "x_y%z.other.org", "qtype": "TXT"}], "b")
    get = lambda **q: client.get("/api/v1/logs/queries", params=q, headers=ADMIN).json()["items"]
    assert len(get()) == 3                                               # default: last 60 minutes
    assert {r["qname"] for r in get(minutes=300)} >= {"old.shop.com"}
    assert [r["host"] for r in get(agent="pc2")] == ["pc2"]
    assert [r["qname"] for r in get(q="mail")] == ["mail.shop.com"]
    assert [r["qtype"] for r in get(qtype="txt")] == ["TXT"]
    assert [r["qname"] for r in get(rcode=3)] == ["mail.shop.com"]
    assert [r["qname"] for r in get(q="x_y%")] == ["x_y%z.other.org"]    # % and _ are not wildcards
    assert get(q="%") == [r for r in get(q="%")] and all("%" in r["qname"] for r in get(q="%"))


def test_query_log_paging_and_validation(client):
    h = agent(client, "pc1")
    send(client, h, [{"ts": time.time(), "qname": "n%d.example.com" % i, "qtype": "A"} for i in range(25)])
    p1 = client.get("/api/v1/logs/queries", params={"limit": 10}, headers=ADMIN).json()
    assert len(p1["items"]) == 10 and p1["next_before_id"]
    p2 = client.get("/api/v1/logs/queries", params={"limit": 10, "before_id": p1["next_before_id"]}, headers=ADMIN).json()
    p3 = client.get("/api/v1/logs/queries", params={"limit": 10, "before_id": p2["next_before_id"]}, headers=ADMIN).json()
    ids = [r["id"] for r in p1["items"] + p2["items"] + p3["items"]]
    assert len(ids) == 25 == len(set(ids)) and ids == sorted(ids, reverse=True) and p3["next_before_id"] is None
    assert client.get("/api/v1/logs/queries", params={"limit": 9999}, headers=ADMIN).status_code == 422
    assert client.get("/api/v1/logs/queries", params={"rcode": 99}, headers=ADMIN).status_code == 422


def test_logs_need_login(client):
    for p in ("queries", "batches", "audit"):
        assert client.get("/api/v1/logs/" + p).status_code == 401


# ---------- agent activity ----------
def test_batch_log_shows_counts(client):
    client.patch("/api/v1/admin/settings", json={"config": {"trusted_domains": ["google.com"]}}, headers=ADMIN)
    h = agent(client, "pc1")
    now = time.time()
    send(client, h, [{"ts": now, "qname": "a.evil.com"}, {"ts": now, "qname": "www.google.com"},
                     {"ts": now, "qname": ""}], "first")
    send(client, h, [{"ts": now, "qname": "b.evil.com"}], "second")
    items = client.get("/api/v1/logs/batches", headers=ADMIN).json()["items"]
    assert [i["batch_id"] for i in items] == ["second", "first"]          # newest first
    assert items[1]["agent"] == "pc1" and (items[1]["accepted"], items[1]["dropped"], items[1]["ignored"]) == (1, 1, 1)


# ---------- audit trail ----------
def test_admin_actions_are_in_the_audit_trail(client):
    aid = client.post("/api/v1/admin/agents", json={"name": "pc1"}, headers=ADMIN).json()["id"]
    client.post("/api/v1/admin/agents/%d/enroll-token" % aid, headers=ADMIN)
    client.patch("/api/v1/admin/agents/%d" % aid, json={"enabled": False}, headers=ADMIN)
    client.patch("/api/v1/admin/settings", json={"config": {"retention_days": 9}}, headers=ADMIN)
    client.post("/api/v1/admin/settings/preset/strict", headers=ADMIN)
    client.post("/api/v1/admin/settings/reset", headers=ADMIN)
    items = client.get("/api/v1/logs/audit", headers=ADMIN).json()["items"]
    acts = [i["action"] for i in items]
    for a in ("agent_created", "install_command_created", "agent_disabled", "settings_changed",
              "preset_applied", "settings_reset"):
        assert a in acts
    assert all(i["actor"] == "api-key" for i in items if i["action"] == "agent_created")
    assert acts[0] == "settings_reset"                                    # newest first


def test_alert_actions_are_audited(client):
    h = agent(client, "pc1")
    send(client, h, tunnel())
    client.post("/api/v1/admin/run/fast", headers=ADMIN)
    aid = client.get("/api/v1/alerts", headers=ADMIN).json()["items"][0]["id"]
    client.patch("/api/v1/alerts/%d" % aid, json={"status": "ack"}, headers=ADMIN)
    client.post("/api/v1/alerts/%d/trust-domain" % aid, headers=ADMIN)
    acts = [i["action"] for i in client.get("/api/v1/logs/audit", headers=ADMIN).json()["items"]]
    assert "alert_ack" in acts and "domain_trusted" in acts


# ---------- alert details (the "detailed view") ----------
def test_alert_details(client):
    h1, h2 = agent(client, "pc1"), agent(client, "pc2")
    send(client, h1, tunnel(), "a"); send(client, h2, tunnel(), "b")
    client.post("/api/v1/admin/run/fast", headers=ADMIN)
    alerts = client.get("/api/v1/alerts?severity=high", headers=ADMIN).json()["items"]
    mine = next(a for a in alerts if a["host"] == "pc1")
    d = client.get("/api/v1/alerts/%d/details" % mine["id"], headers=ADMIN).json()

    assert d["alert"]["id"] == mine["id"] and d["window"]["seconds"] == 300
    s = d["summary"]
    assert s["queries"] == 280 and s["unique_names"] == 280 and s["bytes_out"] == 280 * 70 and s["bytes_in"] == 280 * 120
    assert s["qtypes"] == [{"value": "TXT", "count": 280}] and s["resolvers"][0]["value"] == "8.8.8.8"
    assert s["rcodes"] == [{"value": 3, "count": 280}]
    tl = d["timeline"]
    assert len(tl["counts"]) == 30 and sum(tl["counts"]) == 280
    assert 0 < len(d["samples"]) <= 25 and {"qname", "qtype", "resolver", "rcode"} <= set(d["samples"][0])
    assert d["other_hosts"] == ["pc2"]                                     # same domain seen from another host
    assert client.get("/api/v1/alerts/999/details", headers=ADMIN).status_code == 404


# ---------- agent details ----------
def test_agent_details(client):
    r = client.post("/api/v1/admin/agents", json={"name": "pc1"}, headers=ADMIN).json()
    send(client, {"X-API-Key": r["api_key"]}, tunnel(40), "z")
    d = client.get("/api/v1/admin/agents/%d/details" % r["id"], headers=ADMIN).json()
    assert d["agent"]["name"] == "pc1" and d["agent"]["total_queries"] == 40
    assert d["recent_batches"][0]["accepted"] == 40
    assert d["top_domains_last_hour"][0] == {"parent": "evil-dns.xyz", "count": 40}
    assert client.get("/api/v1/admin/agents/99/details", headers=ADMIN).status_code == 404


# ---------- presets ----------
def test_presets(client):
    names = [p["name"] for p in client.get("/api/v1/admin/settings/presets", headers=ADMIN).json()]
    assert names == ["relaxed", "balanced", "strict"]
    cur = lambda: client.get("/api/v1/admin/settings", headers=ADMIN).json()["profiles"]
    client.post("/api/v1/admin/settings/preset/strict", headers=ADMIN)
    assert cur()["fast"]["severity"] == {"low": 30, "medium": 50, "high": 70}
    client.post("/api/v1/admin/settings/preset/relaxed", headers=ADMIN)
    assert cur()["slow"]["min_signals"] == 4 and cur()["fast"]["severity"]["high"] == 90
    client.post("/api/v1/admin/settings/preset/balanced", headers=ADMIN)
    assert cur()["fast"]["severity"] == {"low": 40, "medium": 60, "high": 80} and cur()["slow"]["min_signals"] == 3
    assert cur()["fast"]["weights"]["entropy"] == 0.20                     # presets never touch weights
    assert client.post("/api/v1/admin/settings/preset/nope", headers=ADMIN).status_code == 404


def test_preset_changes_what_gets_alerted(client):
    h = agent(client, "pc1")
    now = time.time()
    rows = [{"ts": now - 280 + i * 20, "qname": "%s.sketchy.net" % rand(26), "qtype": "TXT"} for i in range(14)]
    send(client, h, rows)
    client.post("/api/v1/admin/settings/preset/relaxed", headers=ADMIN)
    relaxed = client.post("/api/v1/admin/run/fast", headers=ADMIN).json()["created"]
    client.post("/api/v1/admin/settings/preset/strict", headers=ADMIN)
    strict = client.post("/api/v1/admin/run/fast", headers=ADMIN).json()["created"]
    assert relaxed <= strict
