"""Real packets from the real network stack. Needs root (raw socket); skipped otherwise."""
import os
import socket
import struct
import threading
import time

import pytest

from agent.dnshollow_agent import capture
from agent.dnshollow_agent.agent import Agent
from agent.dnshollow_agent.config import AgentConfig
from tests.helpers import dns_msg


def can_capture():
    if not hasattr(os, "geteuid") or os.geteuid() != 0 or not hasattr(socket, "AF_PACKET"):
        return False
    try:
        capture.open_socket().close()
        return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not can_capture(), reason="needs root and raw sockets")


class Quiet:
    """Pretends to be the manager and remembers every record the agent sends."""
    def __init__(self):
        self.sent = []

    def heartbeat(self, _os, blocking=None): return 200, {}

    def ingest(self, batch):
        self.sent.extend(batch["queries"])
        return 200, {}


def start_agent(tmp_path, include_loopback):
    cfg = AgentConfig(server="http://m.lan:1", api_key="k", spool_dir=str(tmp_path), include_loopback=include_loopback)
    agent = Agent(cfg, client=Quiet())
    sock = capture.open_socket()
    t = threading.Thread(target=capture.reader, args=(sock, agent, agent.stop, include_loopback), daemon=True)
    t.start()
    return agent, sock


def collect(agent, seconds=1.5):
    end = time.time() + seconds
    while time.time() < end:
        agent.step(wait=0.1)
    agent._accept(agent.pairer.flush_expired(force=True))
    return agent.client.sent + agent.buffer


def stop(agent, sock):
    agent.stop.set(); time.sleep(1.1); sock.close()


def test_real_outgoing_query_is_captured_on_the_wire(tmp_path):
    agent, sock = start_agent(tmp_path, include_loopback=False)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(dns_msg("real-capture-test.example.org", 16, txid=0x4242), ("8.8.8.8", 53))
        recs = collect(agent)
    finally:
        stop(agent, sock)
    mine = [r for r in recs if r["qname"] == "real-capture-test.example.org"]
    assert len(mine) == 1
    r = mine[0]
    assert (r["resolver"], r["proto"], r["qtype"]) == ("8.8.8.8", "udp", "TXT") and r["qbytes"] > 30


def test_loopback_resolver_is_ignored_by_default_but_pairs_when_enabled(tmp_path):
    def fake_resolver(stop_evt, ready):
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            srv.bind(("127.0.0.1", 53))
        except OSError:
            ready.append(False); return
        srv.settimeout(0.2); ready.append(True)
        while not stop_evt.is_set():
            try:
                data, addr = srv.recvfrom(512)
            except socket.timeout:
                continue
            flags = struct.pack("!H", 0x8183)                 # response, NXDOMAIN
            srv.sendto(data[:2] + flags + data[4:], addr)
        srv.close()

    for include, expect in ((False, 0), (True, 1)):
        stop_evt, ready = threading.Event(), []
        threading.Thread(target=fake_resolver, args=(stop_evt, ready), daemon=True).start()
        time.sleep(0.3)
        if not ready or not ready[0]:
            pytest.skip("cannot bind 127.0.0.1:53 here")
        agent, sock = start_agent(tmp_path / str(include), include_loopback=include)
        try:
            c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.settimeout(2)
            c.sendto(dns_msg("loop-test.example.org", 1, txid=0x0777), ("127.0.0.1", 53))
            c.recvfrom(512)
            recs = [r for r in collect(agent) if r["qname"] == "loop-test.example.org"]
        finally:
            stop(agent, sock); stop_evt.set(); time.sleep(0.3)
        assert len(recs) == expect
        if expect:
            assert recs[0]["rcode"] == 3 and recs[0]["rbytes"] > 0 and recs[0]["resolver"] == "127.0.0.1"
