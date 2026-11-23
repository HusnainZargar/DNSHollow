"""Agent side: command building for Linux and Windows (fake runner), and how the agent applies the list."""
import threading

from agent.dnshollow_agent import blocker as B
from agent.dnshollow_agent import capture_win as W
from agent.dnshollow_agent.agent import Agent
from agent.dnshollow_agent.config import AgentConfig
from tests.helpers import query_pkt, response_pkt, tcp4, udp4


class Rec:
    """Records every command; `fail` maps a substring to (rc, err)."""
    def __init__(self, fail=None):
        self.calls, self.fail = [], fail or {}

    def __call__(self, cmd, stdin=None, timeout=60):
        self.calls.append((cmd, stdin))
        key = " ".join(cmd)
        for k, (rc, err) in self.fail.items():
            if k in key:
                return rc, "", err
        return (1 if "-C" in cmd or "-D" in cmd or ("-L" in cmd and "DNSHOLLOW" in cmd) else 0), "", ""


# ---------- validation ----------
def test_safe_domains_filters_and_protects():
    out = B.safe_domains(["Evil.com", "evil.com.", "bad..x", "com", "a b.com", "x" * 130 + ".com",
                          "manager.corp.lan", "corp.lan", "good.net", "trusted.org", "sub.trusted.org"],
                         protect=["manager.corp.lan", "trusted.org"])
    assert out == ["evil.com", "good.net"]
    assert len(B.safe_domains(["d%d.com" % i for i in range(900)])) == B.MAX_DOMAINS


# ---------- linux ----------
def test_wire_pattern_and_rules():
    assert B.wire_pattern("evil.com") == b"\x04evil\x03com\x00"
    assert B.hex_pattern("a.io") == "|01 61 02 69 6f 00|"
    t = B.restore_text(["evil.com"])
    assert t.startswith("*filter\n-F DNSHOLLOW\n") and t.endswith("COMMIT\n")
    assert t.count("-j DROP") == 2 and "--dport 53" in t and "|04 65 76 69 6c 03 63 6f 6d 00|" in t


def test_linux_sync_builds_chain_jump_and_restore():
    r = Rec()
    b = B.LinuxBlocker(run=r, which=lambda n: "/sbin/" + n)
    assert b.sync(["evil.com"]) == ["evil.com"]
    cmds = [" ".join(c) for c, _ in r.calls]
    assert any("-N DNSHOLLOW" in c for c in cmds) and any("-I OUTPUT 1 -j DNSHOLLOW" in c for c in cmds)
    restores = [(c, s) for c, s in r.calls if c[0].endswith("-restore")]
    assert [c[0] for c, _ in restores] == ["iptables-restore", "ip6tables-restore"]
    assert "evil.com" not in restores[0][1] and "--icase" in restores[0][1]


def test_linux_falls_back_without_icase_and_reports_errors():
    r = Rec({"iptables-restore": (2, "unknown option --icase")})
    b = B.LinuxBlocker(run=r, which=lambda n: "/x")
    try:
        b.sync(["evil.com"])
    except B.BlockerError:
        pass
    stdins = [s for c, s in r.calls if c[0] == "iptables-restore"]
    assert "--icase" in stdins[0] and "--icase" not in stdins[1]
    ok, why = B.LinuxBlocker(run=r, which=lambda n: None).available()
    assert not ok and "iptables" in why
    ok, why = B.LinuxBlocker(run=Rec({"-L OUTPUT": (4, "Permission denied")}), which=lambda n: "/x").available()
    assert not ok and "Permission denied" in why


def test_linux_clear_removes_jump_and_chain():
    r = Rec()
    B.LinuxBlocker(run=r, which=lambda n: "/x").clear()
    cmds = [" ".join(c) for c, _ in r.calls]
    assert any("-F DNSHOLLOW" in c for c in cmds) and any("-X DNSHOLLOW" in c for c in cmds)


# ---------- windows ----------
def test_windows_script_is_fixed_and_domains_go_on_stdin():
    seen = {}

    def run(cmd, stdin, timeout):
        seen.update(cmd=cmd, stdin=stdin)
        return 0, "DNSHOLLOW_OK\n", ""
    b = B.WindowsBlocker(run=run, which=lambda n: "x", is_admin=lambda: True)
    assert b.sync(["evil.com", "bad.net"]) == ["evil.com", "bad.net"]
    assert seen["stdin"] == "evil.com\nbad.net" and "-EncodedCommand" in seen["cmd"]
    assert "evil.com" not in seen["cmd"][-1]
    import base64
    assert base64.b64decode(seen["cmd"][-1]).decode("utf-16-le") == B.NRPT_SCRIPT
    assert "Add-DnsClientNrptRule" in B.NRPT_SCRIPT and "'DNSHollow'" in B.NRPT_SCRIPT


def test_windows_errors_and_admin_check():
    b = B.WindowsBlocker(run=lambda *a: (1, "DNSHOLLOW_ERR Access is denied\n", ""), which=lambda n: "x", is_admin=lambda: True)
    try:
        b.sync(["evil.com"])
        assert False
    except B.BlockerError as e:
        assert "Access is denied" in str(e)
    assert B.WindowsBlocker(which=lambda n: "x", is_admin=lambda: False).available()[0] is False


# ---------- agent applies the manager's list ----------
class FakeBlocker:
    method = "fake"

    def __init__(self, fail=False):
        self.synced, self.fail = [], fail

    def available(self):
        return True, ""

    def sync(self, d):
        if self.fail:
            raise B.BlockerError("boom")
        self.synced.append(list(d))
        return list(d)


class HbClient:
    def __init__(self, blocking):
        self.blocking, self.reports = blocking, []

    def ingest(self, batch):
        return 200, {"blocks_rev": 9}

    def heartbeat(self, os_name, blocking=None):
        self.reports.append(blocking)
        return 200, {"config": {"blocking": self.blocking}}


def make(tmp_path, client, fb):
    return Agent(AgentConfig("http://manager.lan:8000", "k", spool_dir=str(tmp_path)), client=client, blocker=fb)


def test_agent_syncs_filters_and_reports(tmp_path):
    fb = FakeBlocker()
    c = HbClient({"enforce": True, "rev": 3, "domains": ["evil.com", "manager.lan", "x"]})
    a = make(tmp_path, c, fb)
    a._heartbeat(1000.0)
    assert fb.synced == [["evil.com"]] and a.blocks_rev == 3          # manager's own name is never blocked
    a._heartbeat(1060.0)
    assert len(fb.synced) == 1                                         # unchanged list: no new commands
    a._heartbeat(1120.0)
    assert c.reports[-1]["enforcing"] and c.reports[-1]["applied"] == ["evil.com"]
    c.blocking = {"enforce": False, "rev": 4, "domains": ["evil.com"]}
    a._heartbeat(1180.0)
    assert fb.synced[-1] == [] and a.block_applied == []


def test_agent_first_sync_clears_old_rules_and_retries_after_error(tmp_path):
    fb = FakeBlocker()
    a = make(tmp_path, HbClient({"enforce": True, "rev": 1, "domains": []}), fb)
    a._heartbeat(1.0)
    assert fb.synced == [[]]                                           # leftovers from an older run are removed
    bad = make(tmp_path, HbClient({"enforce": True, "rev": 1, "domains": ["evil.com"]}), FakeBlocker(fail=True))
    bad._heartbeat(1.0)
    assert bad.block_error == "boom" and bad.block_report()["error"] == "boom" and not bad.block_report()["enforcing"]
    bad.blocker.fail = False
    bad._heartbeat(61.0)
    assert bad.block_error == "" and bad.block_applied == ["evil.com"]


def test_agent_without_blocking_reports_it_and_ingest_rev_triggers_heartbeat(tmp_path):
    a = make(tmp_path, HbClient({"enforce": True, "rev": 1, "domains": ["evil.com"]}), None)
    a._heartbeat(1.0)
    rep = a.block_report()
    assert not rep["capable"] and "not enabled" in rep["error"]
    a.last_hb = 1000.0
    a._note_rev({"blocks_rev": 5}, 1100.0)
    assert a.last_hb == 0.0


# ---------- windows capture ----------
def test_quick_filter():
    assert W.quick_is_dns(query_pkt("a.com")) and W.quick_is_dns(response_pkt("a.com"))
    assert W.quick_is_dns(tcp4("1.1.1.1", "2.2.2.2", 40000, 53, b"x" * 20))
    assert not W.quick_is_dns(udp4("1.1.1.1", "2.2.2.2", 1, 443, b"x" * 20))
    assert not W.quick_is_dns(udp4("1.1.1.1", "2.2.2.2", 1, 53, b"x" * 20, frag=0x2000))
    assert not W.quick_is_dns(b"\x60" + b"\0" * 60) and not W.quick_is_dns(b"")


def test_windows_capture_direction_and_rescan():
    import socket
    import time
    pairs, got = {}, []

    def opener(ip):
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        pairs[ip] = b
        return a
    ips = {"192.168.1.5"}

    class Sink:
        def feed(self, ts, kind, data):
            got.append((kind, data))
    stop = threading.Event()
    cap = W.WindowsCapture(Sink(), stop, addresses=lambda: ips, opener=opener)
    cap.open()
    t = threading.Thread(target=cap.run, daemon=True)
    t.start()
    pairs["192.168.1.5"].send(query_pkt("a.com", src="192.168.1.5"))      # we sent it
    pairs["192.168.1.5"].send(response_pkt("a.com", dst="192.168.1.5"))   # it came back
    pairs["192.168.1.5"].send(udp4("1.1.1.1", "192.168.1.5", 1, 443, b"x" * 30))   # not DNS
    deadline = time.time() + 3
    while len(got) < 2 and time.time() < deadline:
        time.sleep(0.05)
    stop.set()
    t.join(3)
    assert [k for k, _ in got] == [W.PACKET_OUTGOING, W.PACKET_HOST]
    ips.clear(); ips.add("10.0.0.9")
    cap2 = W.WindowsCapture(Sink(), threading.Event(), addresses=lambda: ips, opener=opener)
    cap2.rescan()
    ips.clear(); ips.add("10.0.0.10")
    cap2.rescan()
    assert set(cap2.socks) == {"10.0.0.10"}
    cap2.close()


def test_windows_capture_fails_clearly_without_admin():
    def opener(ip):
        raise OSError("Access denied")
    cap = W.WindowsCapture(None, threading.Event(), addresses=lambda: {"10.0.0.1"}, opener=opener)
    try:
        cap.open()
        assert False
    except OSError as e:
        assert "Access denied" in str(e)
