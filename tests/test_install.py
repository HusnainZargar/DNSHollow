import io
import sqlite3
import subprocess
import tarfile
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from manager import bundle
from manager.api.main import create_app
from manager.db import Database

ADMIN = {"X-Admin-Key": "adm"}


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(str(tmp_path / "i.db"), scheduler=False, admin_key="adm")) as c:
        yield c


def new_agent(c, name="pc1"):
    return c.post("/api/v1/admin/agents", json={"name": name, "os": "linux"}, headers=ADMIN).json()["id"]


def token_for(c, agent_id):
    return c.post(f"/api/v1/admin/agents/{agent_id}/enroll-token", headers=ADMIN).json()


# ---------- enrollment ----------
def test_enroll_token_needs_admin(client):
    aid = new_agent(client)
    assert client.post(f"/api/v1/admin/agents/{aid}/enroll-token").status_code == 401
    assert client.post("/api/v1/admin/agents/99/enroll-token", headers=ADMIN).status_code == 404


def test_enroll_gives_working_key_once(client):
    aid = new_agent(client)
    t = token_for(client, aid)
    assert t["expires_in"] == 900 and len(t["sha256"]) == 64 and t["agent"] == "pc1"

    r = client.post("/api/v1/agent/enroll", json={"token": t["token"], "os": "Linux 6.1"})
    assert r.status_code == 200
    d = r.json()
    assert d["name"] == "pc1" and d["api_key"].startswith("dh_agent_") and "trusted_domains" in d["config"]
    h = {"X-API-Key": d["api_key"]}
    assert client.get("/api/v1/agent/config", headers=h).status_code == 200
    assert client.get("/api/v1/admin/agents", headers=ADMIN).json()[0]["os"] == "Linux 6.1"

    # the token cannot be used again
    assert client.post("/api/v1/agent/enroll", json={"token": t["token"]}).status_code == 401


def test_enroll_replaces_old_key(client):
    r = client.post("/api/v1/admin/agents", json={"name": "pc1"}, headers=ADMIN).json()
    old = {"X-API-Key": r["api_key"]}
    assert client.get("/api/v1/agent/config", headers=old).status_code == 200
    t = token_for(client, r["id"])
    client.post("/api/v1/agent/enroll", json={"token": t["token"]})
    assert client.get("/api/v1/agent/config", headers=old).status_code == 401


def test_expired_and_wrong_tokens_rejected(client):
    aid = new_agent(client)
    tok = client.app.state.db.create_enroll_token(aid, ttl=-1)
    assert client.post("/api/v1/agent/enroll", json={"token": tok}).status_code == 401
    assert client.post("/api/v1/agent/enroll", json={"token": "dh_enroll_wrong_wrong"}).status_code == 401
    assert client.post("/api/v1/agent/enroll", json={"token": "x"}).status_code == 422


def test_enroll_guessing_is_rate_limited(client):
    codes = [client.post("/api/v1/agent/enroll", json={"token": "dh_enroll_guess_%d" % i}).status_code
             for i in range(12)]
    assert codes[:10] == [401] * 10 and codes[10:] == [429, 429]


def test_disabled_agent_cannot_enroll(client):
    aid = new_agent(client)
    t = token_for(client, aid)
    client.patch(f"/api/v1/admin/agents/{aid}", json={"enabled": False}, headers=ADMIN)
    assert client.post("/api/v1/agent/enroll", json={"token": t["token"]}).status_code == 403


def test_tokens_are_stored_hashed(client):
    aid = new_agent(client)
    t = token_for(client, aid)["token"]
    with client.app.state.db.conn() as c:
        assert t not in c.execute("SELECT token_hash FROM enroll_tokens").fetchone()[0]


# ---------- bundle + installer ----------
def test_bundle_matches_announced_checksum_and_has_the_agent(client):
    aid = new_agent(client)
    announced = token_for(client, aid)["sha256"]
    r = client.get("/api/v1/agent/bundle.tar.gz")
    assert r.status_code == 200 and r.headers["x-sha256"] == announced
    import hashlib
    assert hashlib.sha256(r.content).hexdigest() == announced
    names = tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz").getnames()
    assert "dnshollow_agent/__main__.py" in names and "dnshollow_agent/agent.py" in names
    assert not any("__pycache__" in n or n.endswith(".pyc") for n in names)


def test_bundle_is_deterministic():
    assert bundle.build()[1] == bundle.build()[1]


def test_bundle_missing_gives_503(client, tmp_path, monkeypatch):
    monkeypatch.setenv("DNSHOLLOW_AGENT_DIR", str(tmp_path / "nothing"))
    aid = new_agent(client)
    assert client.get("/api/v1/agent/bundle.tar.gz").status_code == 503
    assert client.post(f"/api/v1/admin/agents/{aid}/enroll-token", headers=ADMIN).status_code == 503


def test_installer_script_is_served_and_valid_bash(client, tmp_path):
    r = client.get("/install/linux.sh")
    assert r.status_code == 200 and r.text.startswith("#!/usr/bin/env bash") and "set -euo pipefail" in r.text
    f = tmp_path / "i.sh"; f.write_text(r.text)
    assert subprocess.run(["bash", "-n", str(f)]).returncode == 0
    for needed in ("--sha256", "Checksum mismatch", "CAP_NET_RAW", "--uninstall", "Restart=always"):
        assert needed in r.text


# ---------- new fields + migration ----------
def test_ingest_stores_resolver_bytes_and_cleans_bad_values(client):
    h = {"X-API-Key": client.post("/api/v1/admin/agents", json={"name": "pc1"}, headers=ADMIN).json()["api_key"]}
    now = time.time()
    body = {"batch_id": "b", "queries": [
        {"ts": now, "qname": "a.evil.com", "qtype": "TXT", "resolver": "9.9.9.9", "proto": "UDP", "qbytes": 60, "rbytes": 300, "rcode": 3},
        {"ts": now, "qname": "b.evil.com", "qtype": "A", "resolver": "x" * 200, "proto": "icmp", "qbytes": -5, "rbytes": 10**9, "rcode": 99},
        {"ts": now, "qname": "c.evil.com", "qtype": "A"}]}                          # old-style record
    assert client.post("/api/v1/agent/ingest", json=body, headers=h).json()["accepted"] == 3
    with client.app.state.db.conn() as c:
        rows = {r["qname"]: dict(r) for r in c.execute("SELECT * FROM queries")}
    a, b, c3 = rows["a.evil.com"], rows["b.evil.com"], rows["c.evil.com"]
    assert (a["resolver"], a["proto"], a["qbytes"], a["rbytes"], a["rcode"]) == ("9.9.9.9", "udp", 60, 300, 3)
    assert len(b["resolver"]) == 64 and b["proto"] is None and b["qbytes"] is None and b["rbytes"] is None and b["rcode"] is None
    assert c3["resolver"] is None and c3["rcode"] is None


def test_old_database_is_upgraded(tmp_path):
    path = tmp_path / "old.db"
    c = sqlite3.connect(path)
    c.executescript("CREATE TABLE queries (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, host TEXT NOT NULL,"
                    " qname TEXT NOT NULL, qtype TEXT NOT NULL, parent TEXT NOT NULL);"
                    "INSERT INTO queries(ts,host,qname,qtype,parent) VALUES (1,'h','a.x.com','A','x.com');")
    c.commit(); c.close()
    db = Database(str(path))
    with db.conn() as conn:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(queries)")}
        assert {"resolver", "proto", "qbytes", "rbytes", "rcode"} <= cols
        assert conn.execute("SELECT COUNT(*) FROM queries").fetchone()[0] == 1
    Database(str(path))                                    # opening twice is fine


# ---------- engine status ----------
def test_stats_report_engine_status(client):
    s = client.get("/api/v1/stats", headers=ADMIN).json()["engine"]
    assert s["scheduler"] is False and s["profiles"]["fast"]["last_run"] is None
    client.post("/api/v1/admin/run/fast", headers=ADMIN)
    s = client.get("/api/v1/stats", headers=ADMIN).json()["engine"]
    assert s["profiles"]["fast"]["ok"] is True and s["profiles"]["fast"]["last_run"] > 0
    assert s["profiles"]["slow"]["last_run"] is None


def test_scheduler_records_engine_runs(tmp_path):
    with TestClient(create_app(str(tmp_path / "s.db"), scheduler=True, admin_key="adm")) as c:
        for _ in range(40):                                # the background loop runs at start-up
            s = c.get("/api/v1/stats", headers=ADMIN).json()["engine"]
            if s["profiles"]["fast"]["last_run"] and s["profiles"]["slow"]["last_run"]:
                break
            time.sleep(0.1)
        assert s["scheduler"] is True and s["profiles"]["fast"]["ok"] and s["profiles"]["slow"]["ok"]
