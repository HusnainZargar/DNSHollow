"""Real HTTP between the agent and a real manager (uvicorn in a thread)."""
import json
import random
import socket
import string
import threading
import time
import urllib.request

import pytest
import uvicorn

from agent.dnshollow_agent.agent import PACKET_OUTGOING, Agent
from agent.dnshollow_agent.client import Client
from agent.dnshollow_agent.config import AgentConfig
from manager.api.main import create_app
from tests.helpers import query_pkt, response_pkt

rng = random.Random(3)
rand = lambda n: "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Manager:
    def __init__(self, path, port):
        self.port = port
        self.app = create_app(path, scheduler=False, admin_key="adm")
        self.server = uvicorn.Server(uvicorn.Config(self.app, host="127.0.0.1", port=port, log_level="error"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self):
        self.thread.start()
        for _ in range(100):
            if self.server.started:
                return self
            time.sleep(0.05)
        raise RuntimeError("manager did not start")

    def stop(self):
        self.server.should_exit = True
        self.thread.join(5)

    def admin(self, method, path, body=None):
        req = urllib.request.Request("http://127.0.0.1:%d/api/v1%s" % (self.port, path), method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"X-Admin-Key": "adm", "Content-Type": "application/json"})
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())


@pytest.fixture
def manager(tmp_path):
    m = Manager(str(tmp_path / "e2e.db"), free_port()).start()
    yield m
    m.stop()


def agent_for(manager, tmp_path, name="lab-pc"):
    made = manager.admin("POST", "/admin/agents", {"name": name, "os": "linux"})
    cfg = AgentConfig(server="http://127.0.0.1:%d" % manager.port, api_key=made["api_key"],
                      spool_dir=str(tmp_path / "spool"))
    a = Agent(cfg)
    a._heartbeat(time.time())
    return a


def traffic(a, names, start, step=1.0, qtype=16, resolver="8.8.8.8"):
    """Feed realistic packets: a query, then its response 20 ms later."""
    for i, name in enumerate(names):
        t, port = start + i * step, 30000 + i % 30000
        a.handle(t, PACKET_OUTGOING, query_pkt(name, dst=resolver, sport=port, txid=i % 65535, qtype=qtype))
        a.handle(t + 0.02, 0, response_pkt(name, src=resolver, dport=port, txid=i % 65535, rcode=3, qtype=qtype))


def test_noisy_tunnel_end_to_end(manager, tmp_path):
    a = agent_for(manager, tmp_path)
    now = time.time()
    names = ["%s.%s.c2.evil-dns.xyz" % (rand(30), rand(18)) for _ in range(280)]
    traffic(a, names, start=now - 290)
    a._send_due(now + 100)                                   # force the batch out
    assert a.stats["sent"] == 280 and a.spool.count() == 0

    run = manager.admin("POST", "/admin/run/fast")
    assert run["created"] == 1
    alert = manager.admin("GET", "/alerts")["items"][0]
    assert alert["parent"] == "evil-dns.xyz" and alert["host"] == "lab-pc" and alert["severity"] == "high"

    with manager.app.state.db.conn() as c:                   # the new fields really arrived
        r = c.execute("SELECT resolver, proto, qbytes, rbytes, rcode, qtype FROM queries LIMIT 1").fetchone()
    assert r["resolver"] == "8.8.8.8" and r["proto"] == "udp" and r["rcode"] == 3 and r["qtype"] == "TXT"
    assert r["qbytes"] > 30 and r["rbytes"] > r["qbytes"]


def test_stealth_tunnel_is_caught_by_slow_profile(manager, tmp_path):
    a = agent_for(manager, tmp_path)
    now = time.time()
    names = ["%s.stealth-c2.net" % rand(40) for _ in range(60)]
    t0 = now - 22 * 3600
    for i, n in enumerate(names):                            # one query every ~22 min, small jitter
        t = t0 + i * 22 * 60 * rng.uniform(0.97, 1.03)
        a.handle(t, PACKET_OUTGOING, query_pkt(n, sport=31000 + i, txid=i, qtype=16))
        a.handle(t + 0.05, 0, response_pkt(n, dport=31000 + i, txid=i, qtype=16))
    a._send_due(now + 100)
    assert manager.admin("POST", "/admin/run/fast")["created"] == 0
    assert manager.admin("POST", "/admin/run/slow")["created"] == 1
    assert manager.admin("GET", "/alerts?profile=slow")["items"][0]["parent"] == "stealth-c2.net"


def test_normal_browsing_makes_no_alert(manager, tmp_path):
    a = agent_for(manager, tmp_path)
    now = time.time()
    names = [rng.choice(["www.shop.com", "cdn.shop.com", "api.shop.com"]) for _ in range(120)]
    traffic(a, names, start=now - 280, step=2.3, qtype=1)
    a._send_due(now + 100)
    assert manager.admin("POST", "/admin/run/fast")["created"] == 0
    assert manager.admin("POST", "/admin/run/slow")["created"] == 0


def test_trusted_list_from_dashboard_reaches_the_agent(manager, tmp_path):
    a = agent_for(manager, tmp_path)
    manager.admin("PATCH", "/admin/settings", {"config": {"trusted_domains": ["shop.com"]}})
    manager.app.state.store._cache = None                    # skip the 5 s settings cache in the test
    a._heartbeat(time.time())
    assert a.trusted == ["shop.com"]
    traffic(a, ["www.shop.com"] * 5, start=time.time() - 10)
    assert a.buffer == []


def test_agent_survives_manager_outage_and_loses_nothing(tmp_path):
    port = free_port()
    m = Manager(str(tmp_path / "o.db"), port).start()
    cfg = AgentConfig(server="http://127.0.0.1:%d" % port,
                      api_key=m.admin("POST", "/admin/agents", {"name": "pc1"})["api_key"],
                      spool_dir=str(tmp_path / "spool"))
    a = Agent(cfg)
    a.client.timeout = 2
    m.stop()                                                  # manager goes down

    now = time.time()
    traffic(a, ["x%d.evil.com" % i for i in range(30)], start=now - 60)
    a._send_due(now + 100)
    assert a.spool.count() == 1 and a.stats["sent"] == 0      # kept on disk

    m2 = Manager(str(tmp_path / "o.db"), port).start()        # same DB, same port: manager is back
    try:
        a.next_ok = 0
        a._catch_up(now + 200)
        assert a.spool.count() == 0 and a.stats["resent"] == 30
        with m2.app.state.db.conn() as c:
            assert c.execute("SELECT COUNT(*) FROM queries").fetchone()[0] == 30
    finally:
        m2.stop()
