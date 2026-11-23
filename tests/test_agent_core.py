import json

import pytest

from agent.dnshollow_agent.agent import PACKET_OUTGOING, Agent
from agent.dnshollow_agent.config import AgentConfig
from agent.dnshollow_agent.spool import Spool
from tests.helpers import query_pkt, response_pkt

HOST_PKT = 0          # PACKET_HOST: arrived at this machine


class FakeClient:
    def __init__(self, statuses=(200,)):
        self.statuses = list(statuses)
        self.calls = []
        self.hb = {"config": {"trusted_domains": ["Google.com"], "batch_interval_seconds": 7, "max_batch_size": 50}}

    def ingest(self, batch):
        self.calls.append(batch)
        s = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
        return s, {}

    def heartbeat(self, os_name, blocking=None):
        self.last_block_report = blocking
        return 200, self.hb


def make(tmp_path, client=None, **cfg):
    c = AgentConfig(server="http://manager.lan:8000", api_key="k", spool_dir=str(tmp_path / "spool"), **cfg)
    a = Agent(c, client=client or FakeClient())
    a.interval, a.max_batch = 10.0, 100
    return a


def out(a, name, ts=100.0, dst="8.8.8.8", **kw):
    a.handle(ts, PACKET_OUTGOING, query_pkt(name, dst=dst, **kw))


def back(a, name, ts=100.1, src="8.8.8.8", **kw):
    a.handle(ts, HOST_PKT, response_pkt(name, src=src, **kw))


def test_query_and_response_become_one_record(tmp_path):
    a = make(tmp_path)
    out(a, "x.example.com"); back(a, "x.example.com", rcode=3)
    assert len(a.buffer) == 1
    r = a.buffer[0]
    assert (r["qname"], r["resolver"], r["rcode"], r["proto"]) == ("x.example.com", "8.8.8.8", 3, "udp")


def test_only_queries_sent_by_this_host_count(tmp_path):
    a = make(tmp_path)
    a.handle(1.0, HOST_PKT, query_pkt("incoming.example.com"))          # we are a DNS server: ignore
    a.handle(1.0, PACKET_OUTGOING, response_pkt("x.example.com"))       # our own answers: ignore
    a.pairer.flush_expired(force=True)
    assert a.buffer == []


def test_loopback_ignored_by_default_and_included_on_request(tmp_path):
    a = make(tmp_path)
    out(a, "x.example.com", dst="127.0.0.53")
    assert a.pairer.pending == {}
    b = make(tmp_path / "b", include_loopback=True)
    out(b, "x.example.com", dst="127.0.0.53")
    assert len(b.pairer.pending) == 1


def test_trusted_and_manager_domains_are_skipped(tmp_path):
    a = make(tmp_path)
    a._heartbeat(0.0)                                     # learns trusted list (lower-cased)
    assert a.trusted == ["google.com"] and a.interval == 7 and a.max_batch == 50
    for n in ("www.google.com", "google.com", "manager.lan", "x.manager.lan"):
        out(a, n); back(a, n)
    out(a, "evil.com"); back(a, "evil.com")
    assert [r["qname"] for r in a.buffer] == ["evil.com"] and a.stats["skipped"] == 4


def test_batch_sent_after_interval(tmp_path):
    a = make(tmp_path)
    out(a, "a.example.com"); back(a, "a.example.com")
    a._send_due(5.0);  assert a.client.calls == []                        # too early
    a._send_due(20.0)
    b = a.client.calls[0]
    assert len(b["queries"]) == 1 and b["batch_id"] and b["agent_version"] and a.stats["sent"] == 1
    assert a.buffer == []


def test_batch_sent_early_when_full(tmp_path):
    a = make(tmp_path); a.max_batch = 3
    for i in range(3):
        out(a, "n%d.example.com" % i, sport=41000 + i, txid=i); back(a, "n%d.example.com" % i, dport=41000 + i, txid=i)
    a._send_due(0.5)
    assert len(a.client.calls) == 1


def test_manager_down_spools_then_recovers_with_same_batch_id(tmp_path):
    cl = FakeClient(statuses=[0, 200])                      # first call fails, then the manager is back
    a = make(tmp_path, cl); a.interval = 1.0
    out(a, "a.example.com"); back(a, "a.example.com")
    a._send_due(20.0)                                       # fails -> spool + backoff until 30
    assert a.spool.count() == 1 and a.stats["spooled"] == 1 and a.next_ok == 30.0
    first_id = cl.calls[0]["batch_id"]

    out(a, "b.example.com", ts=21.0); back(a, "b.example.com", ts=21.1)
    a._send_due(25.0)                                       # still backing off -> straight to disk
    assert a.spool.count() == 2 and len(cl.calls) == 1      # manager was not hammered

    a._catch_up(29.0);  assert len(cl.calls) == 1           # backoff not over
    a._catch_up(31.0)                                       # manager is back: oldest batch goes first
    assert cl.calls[1]["batch_id"] == first_id and a.spool.count() == 1   # same id: server dedupes
    a._catch_up(35.0)
    assert a.spool.count() == 0 and a.stats["resent"] == 2


def test_spool_drains_oldest_first_and_empties(tmp_path):
    a = make(tmp_path, FakeClient(statuses=[200]))
    sp = a.spool
    for i in range(3):
        sp.save({"batch_id": "id%d" % i, "queries": [{"qname": "q%d.com" % i}]})
    for t in (100, 110, 120):
        a._catch_up(float(t))
    assert [c["batch_id"] for c in a.client.calls] == ["id0", "id1", "id2"] and sp.count() == 0


def test_catch_up_is_rate_limited(tmp_path):
    a = make(tmp_path)
    for i in range(3):
        a.spool.save({"batch_id": "id%d" % i, "queries": []})
    a._catch_up(100.0); a._catch_up(101.0)
    assert len(a.client.calls) == 1


def test_auth_failure_keeps_data_and_backs_off(tmp_path):
    a = make(tmp_path, FakeClient(statuses=[401]))
    out(a, "a.example.com"); back(a, "a.example.com")
    a._send_due(20.0)
    assert a.spool.count() == 1 and a.next_ok > 20.0


def test_invalid_batch_is_dropped_not_retried_forever(tmp_path):
    a = make(tmp_path, FakeClient(statuses=[422]))
    out(a, "a.example.com"); back(a, "a.example.com")
    a._send_due(20.0)
    assert a.spool.count() == 0 and a.stats["poison_dropped"] == 1


def test_too_large_batch_is_split(tmp_path):
    cl = FakeClient(statuses=[413, 200, 200])
    a = make(tmp_path, cl)
    for i in range(4):
        out(a, "n%d.example.com" % i, sport=41000 + i, txid=i); back(a, "n%d.example.com" % i, dport=41000 + i, txid=i)
    a._send_due(20.0)
    assert [len(c["queries"]) for c in cl.calls] == [4, 2, 2] and a.spool.count() == 0


def test_spool_size_cap_drops_oldest(tmp_path):
    sp = Spool(tmp_path / "s", max_bytes=3000)
    for i in range(10):
        sp.save({"batch_id": "id%02d" % i, "queries": [{"qname": "x" * 400}]})
    names = [p.name for p in sp._files()]
    assert sp.dropped > 0 and names[-1].endswith("id09.json") and "id00" not in "".join(names)


def test_spool_ignores_corrupt_file(tmp_path):
    sp = Spool(tmp_path / "s")
    (sp.dir / "00000000000000000001-bad.json").write_text("{not json")
    assert sp.load(sp.oldest()) is None and sp.count() == 0


def test_shutdown_flushes_pending_to_manager(tmp_path):
    a = make(tmp_path)
    out(a, "a.example.com")                                 # query still waiting for a response
    a.shutdown()
    assert len(a.client.calls) == 1 and a.client.calls[0]["queries"][0]["rcode"] is None


def test_full_queue_drops_and_counts(tmp_path):
    a = make(tmp_path)
    a.q.maxsize = 2
    for _ in range(5):
        a.feed(1.0, 4, b"x")
    assert a.stats["queue_dropped"] == 3
