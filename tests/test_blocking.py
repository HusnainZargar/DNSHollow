"""Blocking: manager rules (manual, from an alert, auto), API, and what agents receive."""
import time

import pytest
from fastapi.testclient import TestClient

from manager.api.main import create_app
from manager.engine.blocking import BlockError, clean_block_domain
from manager.engine.runner import run_profile
from manager.engine.settings import merge_settings
from tests.test_runner import NOW, add, db, fast_tunnel  # noqa: F401  (db = fixture)

ADMIN = {"X-Admin-Key": "adm"}


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(str(tmp_path / "b.db"), scheduler=False, admin_key="adm")) as c:
        yield c


def agent(c, name="pc1"):
    r = c.post("/api/v1/admin/agents", json={"name": name}, headers=ADMIN).json()
    return {"X-API-Key": r["api_key"]}


# ---------- domain checks ----------
@pytest.mark.parametrize("bad", ["", "com", "co.uk", "1.2.3.4", "a b.com", "x.evil.com", "-bad-.com", "a..com"])
def test_refuses_dangerous_or_malformed_names(bad):
    with pytest.raises(BlockError):
        clean_block_domain(bad, [])


def test_refuses_trusted_and_normalizes():
    assert clean_block_domain(" Evil-DNS.XYZ. ", []) == "evil-dns.xyz"
    with pytest.raises(BlockError):
        clean_block_domain("google.com", ["google.com"])


# ---------- API ----------
def test_manual_block_reaches_only_the_right_agents(client):
    h1, h2 = agent(client, "pc1"), agent(client, "pc2")
    r = client.post("/api/v1/blocks", json={"parent": "evil.xyz", "scope": "host", "host": "pc1"}, headers=ADMIN)
    assert r.status_code == 201 and r.json()["created"]
    b1 = client.post("/api/v1/agent/heartbeat", json={}, headers=h1).json()["config"]["blocking"]
    b2 = client.post("/api/v1/agent/heartbeat", json={}, headers=h2).json()["config"]["blocking"]
    assert b1["domains"] == ["evil.xyz"] and b1["enforce"] and b2["domains"] == []
    client.post("/api/v1/blocks", json={"parent": "bad.net", "scope": "all"}, headers=ADMIN)
    assert client.post("/api/v1/agent/heartbeat", json={}, headers=h2).json()["config"]["blocking"]["domains"] == ["bad.net"]


def test_duplicate_and_wider_blocks_are_reused(client):
    agent(client)
    a = client.post("/api/v1/blocks", json={"parent": "evil.xyz", "scope": "all"}, headers=ADMIN).json()
    b = client.post("/api/v1/blocks", json={"parent": "evil.xyz", "scope": "host", "host": "pc1"}, headers=ADMIN).json()
    assert b["id"] == a["id"] and not b["created"]


def test_validation_errors(client):
    agent(client)
    assert client.post("/api/v1/blocks", json={"parent": "co.uk", "scope": "all"}, headers=ADMIN).status_code == 422
    assert client.post("/api/v1/blocks", json={"parent": "x.com", "scope": "host", "host": "nope"}, headers=ADMIN).status_code == 422
    assert client.post("/api/v1/blocks", json={"parent": "x.com", "scope": "all"}).status_code == 401


def test_unblock_removes_it_and_calms_open_alerts(client):
    h = agent(client)
    db = client.app.state.db
    aid, _ = db.upsert_alert("fast", "pc1", "evil.xyz", 95, "high", "s", [], time.time())
    r = client.post(f"/api/v1/alerts/{aid}/block", json={"scope": "host"}, headers=ADMIN)
    assert r.status_code == 201
    al = client.get(f"/api/v1/alerts/{aid}", headers=ADMIN).json()
    assert al["blocks"][0]["scope"] == "host"
    bid = r.json()["id"]
    assert client.delete(f"/api/v1/blocks/{bid}", headers=ADMIN).json()["alerts_acknowledged"] == 1
    assert client.post("/api/v1/agent/heartbeat", json={}, headers=h).json()["config"]["blocking"]["domains"] == []
    assert db.get_alert(aid)["status"] == "ack"
    assert client.delete(f"/api/v1/blocks/{bid}", headers=ADMIN).status_code == 404


def test_not_a_threat_and_trust_lift_blocks(client):
    agent(client)
    db = client.app.state.db
    aid, _ = db.upsert_alert("fast", "pc1", "evil.xyz", 95, "high", "s", [], time.time())
    client.post(f"/api/v1/alerts/{aid}/block", json={"scope": "all"}, headers=ADMIN)
    assert client.patch(f"/api/v1/alerts/{aid}", json={"status": "false_positive"}, headers=ADMIN).json()["blocks_removed"] == 1
    client.post("/api/v1/blocks", json={"parent": "evil.xyz", "scope": "all"}, headers=ADMIN)
    aid2, _ = db.upsert_alert("slow", "pc1", "evil.xyz", 95, "high", "s", [], time.time())
    assert client.post(f"/api/v1/alerts/{aid2}/trust-domain", headers=ADMIN).json()["blocks_removed"] == 1


def test_master_switch_off_stops_everything(client):
    h = agent(client)
    client.post("/api/v1/blocks", json={"parent": "evil.xyz", "scope": "all"}, headers=ADMIN)
    client.patch("/api/v1/admin/settings", json={"config": {"blocking": {"enabled": False}}}, headers=ADMIN)
    cfg = client.post("/api/v1/agent/heartbeat", json={}, headers=h).json()["config"]["blocking"]
    assert cfg == {"enforce": False, "rev": cfg["rev"], "domains": []}
    assert client.post("/api/v1/blocks", json={"parent": "x.com", "scope": "all"}, headers=ADMIN).status_code == 409


def test_timed_block_expires(client):
    h = agent(client)
    db = client.app.state.db
    db.add_block("evil.xyz", "", "manual", expires_at=time.time() + 100)
    assert db.blocks_for_agent("pc1") == ["evil.xyz"]
    assert db.blocks_for_agent("pc1", now=time.time() + 200) == []
    assert db.expire_blocks(time.time() + 200) == 1


def test_agent_report_is_stored_and_ingest_tells_the_rev(client):
    h = agent(client)
    rep = {"capable": True, "enforcing": True, "method": "iptables", "applied": ["evil.xyz"], "error": ""}
    client.post("/api/v1/agent/heartbeat", json={"blocking": rep}, headers=h)
    a = client.get("/api/v1/admin/agents", headers=ADMIN).json()[0]
    assert a["blocking"]["applied"] == ["evil.xyz"] and a["blocking"]["method"] == "iptables"
    client.post("/api/v1/blocks", json={"parent": "evil.xyz", "scope": "all"}, headers=ADMIN)
    r = client.post("/api/v1/agent/ingest", json={"batch_id": "x", "queries": []}, headers=h).json()
    assert r["blocks_rev"] == client.app.state.db.blocks_rev() > 0


def test_settings_validation(client):
    for bad in ({"auto_min_score": 0}, {"auto_scope": "x"}, {"auto_expire_hours": -1}, {"auto_block": "yes"}):
        assert client.patch("/api/v1/admin/settings", json={"config": {"blocking": bad}}, headers=ADMIN).status_code == 422


# ---------- auto-block in the engine ----------
def auto_settings(**kw):
    s = merge_settings(None)
    s["blocking"].update(auto_block=True, auto_min_score=80, **kw)
    return s


def test_auto_block_fires_at_threshold(db):
    add(db, "pc1", fast_tunnel())
    stats = run_profile(db, auto_settings(), "fast", NOW)
    assert stats["blocked"] == 1
    assert db.blocks_for_agent("pc1", NOW) == ["evil-dns.xyz"]
    assert db.blocks_for_agent("other", NOW) == []                 # scope "host" by default
    b = db.list_blocks(now=NOW)[0]
    assert b["source"] == "auto" and b["expires_at"] == NOW + 24 * 3600 and b["alert_id"]
    assert run_profile(db, auto_settings(), "fast", NOW + 30)["blocked"] == 0   # not blocked twice


def test_auto_block_scope_all(db):
    add(db, "pc1", fast_tunnel())
    run_profile(db, auto_settings(auto_scope="all"), "fast", NOW)
    assert db.blocks_for_agent("another-pc", NOW) == ["evil-dns.xyz"]


def test_auto_block_is_off_by_default_and_respects_threshold(db):
    add(db, "pc1", fast_tunnel())
    assert run_profile(db, merge_settings(None), "fast", NOW)["blocked"] == 0
    s = auto_settings(); s["blocking"]["auto_min_score"] = 100
    assert run_profile(db, s, "fast", NOW + 1)["blocked"] == 0
    assert db.list_blocks(now=NOW) == []


def test_auto_block_skips_reviewed_alerts_and_master_off(db):
    add(db, "pc1", fast_tunnel())
    s = merge_settings(None)
    run_profile(db, s, "fast", NOW)
    aid = db.list_alerts()[0][0]["id"]
    db.set_alert_status(aid, "ack")                                # someone is looking into it
    assert run_profile(db, auto_settings(), "fast", NOW + 30)["blocked"] == 0
    db.set_alert_status(aid, "open")
    off = auto_settings(); off["blocking"]["enabled"] = False
    assert run_profile(db, off, "fast", NOW + 60)["blocked"] == 0
    assert run_profile(db, auto_settings(), "fast", NOW + 90)["blocked"] == 1


def test_windows_installer_is_served_and_ascii(client):
    r = client.get("/install/windows.ps1")
    assert r.status_code == 200 and "param(" in r.text and "-EnableBlocking" in r.text
    assert r.text.isascii()                                    # no BOM / encoding surprises in PowerShell 5.1
    assert "--enable-blocking" in client.get("/install/linux.sh").text
