import random
import string

import pytest

from manager.db import Database
from manager.engine.runner import purge_old, run_profile
from manager.engine.settings import merge_settings

NOW = 1_000_000.0
rng = random.Random(5)


def rand(n):
    return "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))


@pytest.fixture
def db(tmp_path):
    d = Database(str(tmp_path / "t.db"))
    d.create_agent("pc1")
    return d


def add(db, host, rows, batch="b"):
    db.insert_batch(1, host, f"{batch}{len(rows)}{rows[0][0]}", rows, NOW)


def fast_tunnel(host="pc1", parent="evil-dns.xyz"):
    return [(NOW - 290 + i, f"{rand(30)}.{rand(18)}.c2.{parent}", "TXT", parent) for i in range(280)]


def slow_tunnel(host="pc1", parent="stealth-c2.net"):
    """60 queries over ~22 h, ~22 min apart with small jitter, long random names."""
    rows, t = [], NOW - 22 * 3600
    for _ in range(60):
        rows.append((t, f"{rand(40)}.{parent}", rng.choice(["TXT", "NULL", "TXT"]), parent))
        t += 22 * 60 * rng.uniform(0.95, 1.05)
    return rows


def normal(parent="shop.com", n=200):
    names = ["www", "cdn", "api"]
    return [(NOW - 80000 + i * 400 + rng.random() * 150, f"{names[i % 3]}.{parent}", "A", parent)
            for i in range(n)]


def alerts(db, **kw):
    return db.list_alerts(**kw)[0]


def test_fast_profile_catches_noisy_tunnel(db):
    add(db, "pc1", fast_tunnel())
    stats = run_profile(db, merge_settings(None), "fast", NOW)
    assert stats["created"] == 1
    a = alerts(db)[0]
    assert a["parent"] == "evil-dns.xyz" and a["severity"] == "high" and a["profile"] == "fast"


def test_slow_tunnel_missed_by_fast_caught_by_slow(db):
    add(db, "pc1", slow_tunnel())
    s = merge_settings(None)
    assert run_profile(db, s, "fast", NOW)["created"] == 0
    assert run_profile(db, s, "slow", NOW)["created"] == 1
    a = alerts(db)[0]
    assert a["parent"] == "stealth-c2.net" and a["profile"] == "slow" and a["severity"] in ("high", "medium")


def test_normal_traffic_makes_no_alert(db):
    add(db, "pc1", normal())
    s = merge_settings(None)
    assert run_profile(db, s, "fast", NOW)["created"] == 0
    assert run_profile(db, s, "slow", NOW)["created"] == 0


def test_second_run_updates_not_duplicates(db):
    add(db, "pc1", fast_tunnel())
    s = merge_settings(None)
    run_profile(db, s, "fast", NOW)
    again = run_profile(db, s, "fast", NOW + 30)
    assert again["updated"] == 1 and again["created"] == 0
    assert alerts(db)[0]["hits"] == 2


def test_trusted_domain_is_skipped(db):
    add(db, "pc1", fast_tunnel(parent="evil-dns.xyz"))
    s = merge_settings({"trusted_domains": ["evil-dns.xyz"]})
    stats = run_profile(db, s, "fast", NOW)
    assert stats["scored"] == 0 and stats["created"] == 0


def test_disabled_profile_does_nothing(db):
    add(db, "pc1", fast_tunnel())
    s = merge_settings({"profiles": {"fast": {"enabled": False}}})
    assert "skipped" in run_profile(db, s, "fast", NOW)
    assert alerts(db) == []


def test_settings_change_changes_outcome(db):
    add(db, "pc1", fast_tunnel())
    strict_off = merge_settings({"profiles": {"fast": {"severity": {"low": 98, "medium": 99, "high": 100}}}})
    assert run_profile(db, strict_off, "fast", NOW)["created"] == 0


def test_two_hosts_same_domain_make_two_alerts_and_a_campaign(db):
    db.create_agent("pc2")
    add(db, "pc1", fast_tunnel())
    rows2 = [(ts, qn, qt, p) for ts, qn, qt, p in fast_tunnel()]
    db.insert_batch(2, "pc2", "x", rows2, NOW)
    run_profile(db, merge_settings(None), "fast", NOW)
    assert len(alerts(db)) == 2
    assert db.campaigns(2)[0]["parent"] == "evil-dns.xyz"


def test_idle_alert_expires(db):
    add(db, "pc1", fast_tunnel())
    s = merge_settings(None)
    run_profile(db, s, "fast", NOW)
    stats = run_profile(db, s, "fast", NOW + 5000)     # data is now outside the window
    assert stats["expired"] == 1
    assert alerts(db)[0]["status"] == "expired"


def test_purge_old(db):
    add(db, "pc1", [(NOW - 10 * 86400, "a.x.com", "A", "x.com"), (NOW - 100, "b.x.com", "A", "x.com")])
    assert purge_old(db, merge_settings(None), NOW) == 1
