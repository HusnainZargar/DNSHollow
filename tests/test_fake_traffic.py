"""The fake-traffic tool must keep producing the alert levels it promises (guards against engine drift)."""
import os
import random
import time

import pytest
from fastapi.testclient import TestClient

from manager.api.main import create_app
from manager.engine.runner import run_profile
from tools import fake_dns_traffic as F

H = {"X-Admin-Key": "adm"}


@pytest.fixture(scope="module")
def alerts(tmp_path_factory):
    with TestClient(create_app(str(tmp_path_factory.mktemp("f") / "f.db"), scheduler=False, admin_key="adm")) as c:
        keys = {n: c.post("/api/v1/admin/agents", json={"name": n}, headers=H).json()["api_key"] for n in F.OS}
        rng, now = random.Random(7), time.time()
        for name, level in F.PLAN["all"]:
            rows = [q.as_dict() for q in F.LEVELS[level](rng, now)]
            for i in range(0, len(rows), 1000):
                r = c.post("/api/v1/agent/ingest", json={"batch_id": os.urandom(6).hex(), "queries": rows[i:i + 1000]},
                           headers={"X-API-Key": keys[name]})
                assert r.status_code == 200
        db, s = c.app.state.db, c.app.state.store.get()
        run_profile(db, s, "fast", now + 1)
        run_profile(db, s, "slow", now + 1)
        items = c.get("/api/v1/alerts?limit=100", headers=H).json()["items"]
        yield items, c.get("/api/v1/campaigns", headers=H).json()


def fast(items, parent):
    return [a for a in items if a["parent"] == parent and a["profile"] == "fast"]


def test_benign_raises_nothing(alerts):
    assert not [a for a in alerts[0] if "example.test" in a["parent"]]


@pytest.mark.parametrize("parent,severity,lo,hi", [
    ("tracker-cdn.test", "low", 40, 59.9), ("sync-update.test", "medium", 60, 79.9),
    ("evil-dns.test", "high", 80, 100), ("exfil-hollow.test", "high", 90, 100)])
def test_levels_land_where_documented(alerts, parent, severity, lo, hi):
    a = fast(alerts[0], parent)
    assert a and a[0]["severity"] == severity and lo <= a[0]["score"] <= hi, [(x["severity"], x["score"]) for x in a]


def test_slow_beacon_is_caught_by_the_slow_profile(alerts):
    a = [x for x in alerts[0] if x["parent"] == "stealth-c2.test"]
    assert a and a[0]["profile"] == "slow"


def test_campaign_spans_three_computers(alerts):
    c = [x for x in alerts[1] if x["parent"] == "botnet-hollow.test"]
    assert c and c[0]["hosts"] == 3 and sorted(c[0]["host_list"]) == sorted(F.OS)
