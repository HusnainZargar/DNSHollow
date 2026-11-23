import sqlite3
import time

import pytest

from manager.db import Database


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "t.db"))


def test_agent_key_roundtrip(db):
    aid, key = db.create_agent("pc1", "linux")
    row = db.get_agent_by_key(key)
    assert row["id"] == aid and row["name"] == "pc1"
    assert db.get_agent_by_key("wrong") is None
    # key is stored hashed, never plain
    with db.conn() as c:
        assert key not in c.execute("SELECT key_hash FROM agents").fetchone()[0]


def test_duplicate_agent_name(db):
    db.create_agent("pc1")
    with pytest.raises(sqlite3.IntegrityError):
        db.create_agent("pc1")


def test_rotate_key_and_disable(db):
    aid, old = db.create_agent("pc1")
    new = db.rotate_agent_key(aid)
    assert db.get_agent_by_key(old) is None
    assert db.get_agent_by_key(new)["id"] == aid
    db.set_agent_enabled(aid, False)
    assert db.get_agent(aid)["enabled"] == 0


def test_insert_batch_and_duplicate(db):
    aid, _ = db.create_agent("pc1")
    rows = [(100.0, "a.evil.com", "A", "evil.com"), (101.0, "b.evil.com", "TXT", "evil.com")]
    assert db.insert_batch(aid, "pc1", "b1", rows, 200.0) == (2, False)
    assert db.insert_batch(aid, "pc1", "b1", rows, 201.0) == (0, True)   # retry ignored
    assert db.get_agent(aid)["total_queries"] == 2
    assert db.candidate_groups(0, 500, 2) == [("pc1", "evil.com", 2)]
    assert db.candidate_groups(0, 500, 3) == []


def test_fetch_group_window(db):
    aid, _ = db.create_agent("pc1")
    db.insert_batch(aid, "pc1", "b", [(10.0, "a.x.com", "A", "x.com"),
                                       (90.0, "b.x.com", "A", "x.com")], 100)
    assert [r[1] for r in db.fetch_group("pc1", "x.com", 50, 100)] == ["b.x.com"]


def test_purge(db):
    aid, _ = db.create_agent("pc1")
    db.insert_batch(aid, "pc1", "b", [(10.0, "a.x.com", "A", "x.com"),
                                       (900.0, "b.x.com", "A", "x.com")], 1000)
    assert db.purge(500) == 1
    assert len(db.fetch_group("pc1", "x.com", 0, 2000)) == 1


def test_alert_lifecycle(db):
    aid, status = db.upsert_alert("fast", "pc1", "evil.com", 90, "high", "s", [{"a": 1}], 100)
    assert status == "created"
    aid2, status = db.upsert_alert("fast", "pc1", "evil.com", 95, "high", "s2", [], 130)
    assert (aid2, status) == (aid, "updated")
    row = db.get_alert(aid)
    assert row["score"] == 95 and row["hits"] == 2 and row["first_seen"] == 100 and row["last_seen"] == 130

    # false positive suppresses future alerts for the same key
    db.set_alert_status(aid, "false_positive")
    assert db.upsert_alert("fast", "pc1", "evil.com", 99, "high", "", [], 200)[1] == "suppressed"
    # other profile / host are independent
    assert db.upsert_alert("slow", "pc1", "evil.com", 99, "high", "", [], 200)[1] == "created"
    assert db.upsert_alert("fast", "pc2", "evil.com", 99, "high", "", [], 200)[1] == "created"


def test_expire_alerts(db):
    a, _ = db.upsert_alert("fast", "pc1", "a.com", 90, "high", "", [], 100)
    b, _ = db.upsert_alert("fast", "pc1", "b.com", 90, "high", "", [], 900)
    assert db.expire_alerts("fast", 500) == 1
    assert db.get_alert(a)["status"] == "expired" and db.get_alert(b)["status"] == "open"
    # a new alert can be created after expiry
    assert db.upsert_alert("fast", "pc1", "a.com", 90, "high", "", [], 1000)[1] == "created"


def test_list_alerts_filters(db):
    db.upsert_alert("fast", "pc1", "a.com", 90, "high", "", [], 100)
    db.upsert_alert("slow", "pc2", "b.com", 50, "low", "", [], 200)
    rows, total = db.list_alerts(severity="high")
    assert total == 1 and rows[0]["parent"] == "a.com"
    rows, total = db.list_alerts()
    assert total == 2 and rows[0]["parent"] == "b.com"      # newest first
    assert db.list_alerts(limit=1, offset=1)[0][0]["parent"] == "a.com"


def test_campaigns(db):
    db.upsert_alert("fast", "pc1", "evil.com", 90, "high", "", [], 100)
    db.upsert_alert("fast", "pc2", "evil.com", 70, "medium", "", [], 100)
    db.upsert_alert("fast", "pc1", "other.com", 95, "high", "", [], 100)
    c = db.campaigns(2)
    assert len(c) == 1 and c[0]["parent"] == "evil.com" and c[0]["hosts"] == 2
    assert db.campaigns(3) == []


def test_stats(db):
    aid, _ = db.create_agent("pc1")
    now = time.time()
    db.insert_batch(aid, "pc1", "b", [(now - 10, "a.x.com", "A", "x.com")], now)
    db.upsert_alert("fast", "pc1", "evil.com", 90, "high", "", [], now)
    s = db.stats(now, 60)
    assert s["alerts_open"]["high"] == 1 and s["agents"] == {"total": 1, "online": 1}
    assert s["queries_last_hour"] == 1


def test_settings_roundtrip_and_meta(db):
    assert db.load_settings() is None
    db.save_settings({"a": 1})
    assert db.load_settings() == {"a": 1}
    db.delete_settings()
    assert db.load_settings() is None
    db.set_meta("k", "v1"); db.set_meta("k", "v2")
    assert db.get_meta("k") == "v2"
