#!/usr/bin/env python3
"""Fake DNS traffic for testing DNSHollow. Standard library only.

It sends made-up DNS queries to the manager, exactly like a real agent would, at
different danger levels, so you can test alerts, scores, campaigns, blocking and
auto-block without running a real tunnel.

  python3 tools/fake_dns_traffic.py --server http://127.0.0.1:8000 --admin-key KEY all
  python3 tools/fake_dns_traffic.py --server http://127.0.0.1:8000 --admin-key KEY high --loop 120

Levels (what you should see):
  benign    normal browsing                      no alert
  low       busy hash-named CDN, plain A records LOW alert   (score ~45)
  medium    TXT-heavy, fairly regular            MEDIUM alert (score ~69)
  high      noisy tunnel (iodine / dnscat2)      HIGH alert   (score ~85)
  critical  everything wrong at once             HIGH alert   (score 100, passes the default auto-block level of 90)
  slow      stealth beacon, 1 query / ~20 min    alert from the SLOW profile (up to 5 min to appear)
  campaign  one bad domain from 3 computers      HIGH alerts + a CAMPAIGN
  all       every level above, each on its own computer

Needs one of:
  --admin-key KEY   creates test agents (sim-linux, sim-windows, sim-extra), saves their keys in
                    .fake-dns-keys.json and reuses them next time
  --key KEY         use one existing agent key (all traffic then appears as that agent)
The admin key is the DNSHOLLOW_ADMIN_KEY you started the manager with.

Each level can show two alerts: one from the FAST profile (last 5 min) and one from the SLOW profile (last
24 h, which also sees this data). The fast one matches the level above. The slow profile runs every 5 minutes.
The fast profile looks at the last 5 minutes, so alerts disappear when the data gets old.
Use --loop SECONDS to keep sending fresh traffic (stop with Ctrl+C).
All domains are fake (.test / made-up names). Nothing leaves your manager.
"""
import argparse
import json
import random
import ssl
import string
import sys
import time
import urllib.error
import urllib.request
import uuid

HEX = "0123456789abcdef"
B32 = string.ascii_lowercase + "234567"
B64 = string.ascii_letters + string.digits


def rnd(rng, n, alphabet=string.ascii_lowercase + string.digits):
    return "".join(rng.choice(alphabet) for _ in range(n))


class Q:
    """One query. Same fields the real agent sends."""
    __slots__ = ("ts", "qname", "qtype", "resolver", "proto", "qbytes", "rbytes", "rcode")

    def __init__(self, ts, qname, qtype="A", resolver="10.0.0.53", proto="udp", qbytes=None, rbytes=None, rcode=0):
        self.ts, self.qname, self.qtype, self.resolver = ts, qname, qtype, resolver
        self.proto, self.qbytes, self.rbytes, self.rcode = proto, qbytes, rbytes, rcode

    def as_dict(self):
        d = {"ts": round(self.ts, 3), "qname": self.qname, "qtype": self.qtype, "resolver": self.resolver,
             "proto": self.proto, "rcode": self.rcode}
        d["qbytes"] = self.qbytes if self.qbytes is not None else 28 + len(self.qname)
        d["rbytes"] = self.rbytes if self.rbytes is not None else 60
        return d


def spread(rng, now, n, span, jitter):
    """n timestamps over the last `span` seconds. jitter 0 = perfectly regular, 1 = random."""
    step = span / n
    t0 = now - span
    return [t0 + i * step + rng.uniform(-0.5, 0.5) * step * jitter * 2 for i in range(n)]


# ------------------------------------------------------------------ levels
def benign(rng, now):
    sites = ["www.shop-example.test", "cdn.shop-example.test", "api.shop-example.test", "mail.corp-example.test",
             "www.news-example.test", "static.news-example.test", "update.os-example.test", "login.corp-example.test"]
    out = [Q(now - rng.uniform(1, 290), rng.choice(sites), rng.choice(["A", "A", "A", "AAAA"]), rcode=0) for _ in range(60)]
    # a day of light browsing so the 24 h window has something normal too
    out += [Q(now - rng.uniform(300, 86000), rng.choice(sites), "A") for _ in range(120)]
    return out


def low(rng, now):
    """Hash-looking CDN names, a brisk, irregular pace, plain A records. Two or three weak signals."""
    d = "tracker-cdn.test"
    return [Q(t, "%s.%s.%s" % (rnd(rng, 20, HEX), rnd(rng, 6, HEX), d), "A")
            for t in spread(rng, now, 230, 280, 1.0)]

def medium(rng, now):
    """TXT-heavy, fairly steady, random-looking labels."""
    d = "sync-update.test"
    out = []
    for t in spread(rng, now, 150, 280, 0.3):
        out.append(Q(t, "%s.%s.%s" % (rnd(rng, 24, B32), rnd(rng, 10, B32), d), rng.choice(["TXT", "TXT", "A", "TXT"])))
    return out

def high(rng, now):
    """iodine / dnscat2 style: lots of TXT, deep names, random base32 labels."""
    d = "evil-dns.test"
    out = []
    for t in spread(rng, now, 300, 285, 0.9):
        out.append(Q(t, "%s.%s.%s.c2.%s" % (rnd(rng, 30, B32), rnd(rng, 18, B32), rnd(rng, 6, B32), d), "TXT", qbytes=130, rbytes=380))
    return out

def critical(rng, now):
    """Fast, machine-regular, NULL/TXT only, very long random labels, huge data volume."""
    d = "exfil-hollow.test"
    out = []
    for t in spread(rng, now, 480, 290, 0.02):
        out.append(Q(t, "%s.%s.%s.x.%s" % (rnd(rng, 58, B32), rnd(rng, 40, B64).lower(), rnd(rng, 20, B32), d),
                     rng.choice(["NULL", "TXT"]), proto="udp", qbytes=210, rbytes=500))
    return out


def slow(rng, now):
    """Stealth beacon: ~60 long random TXT/NULL queries, one every ~22 minutes, for 22 hours."""
    d = "stealth-c2.test"
    out, t = [], now - 22 * 3600
    for _ in range(60):
        out.append(Q(t, "%s.%s" % (rnd(rng, 40, B32), d), rng.choice(["TXT", "NULL", "TXT"]), qbytes=90, rbytes=300))
        t += 22 * 60 * rng.uniform(0.95, 1.05)
    return out


def campaign(rng, now):
    """The same bad domain, from several computers (called once per computer)."""
    d = "botnet-hollow.test"
    out = []
    for t in spread(rng, now, 280, 285, 0.9):
        out.append(Q(t, "%s.%s.%s.up.%s" % (rnd(rng, 28, B32), rnd(rng, 16, B32), rnd(rng, 6, B32), d), "TXT", qbytes=125, rbytes=360))
    return out

LEVELS = {"benign": benign, "low": low, "medium": medium, "high": high, "critical": critical,
          "slow": slow, "campaign": campaign}

# which test computer sends what
PLAN = {
    "all": [("sim-linux", "benign"), ("sim-windows", "benign"), ("sim-linux", "low"), ("sim-windows", "medium"),
            ("sim-linux", "high"), ("sim-windows", "critical"), ("sim-extra", "slow"),
            ("sim-linux", "campaign"), ("sim-windows", "campaign"), ("sim-extra", "campaign")],
    "benign": [("sim-linux", "benign")], "low": [("sim-linux", "low")], "medium": [("sim-windows", "medium")],
    "high": [("sim-linux", "high")], "critical": [("sim-windows", "critical")], "slow": [("sim-extra", "slow")],
    "campaign": [("sim-linux", "campaign"), ("sim-windows", "campaign"), ("sim-extra", "campaign")],
}
OS = {"sim-linux": "Linux 6.8 (fake)", "sim-windows": "Windows 11 (fake)", "sim-extra": "Linux 5.15 (fake)"}


# ------------------------------------------------------------------ http
class Manager:
    def __init__(self, server, insecure):
        self.server = server.rstrip("/")
        self.ctx = ssl._create_unverified_context() if insecure else None

    def call(self, method, path, body=None, headers=None):
        req = urllib.request.Request(self.server + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers=dict({"Content-Type": "application/json"}, **(headers or {})))
        try:
            with urllib.request.urlopen(req, timeout=30, context=self.ctx) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except ValueError:
                return e.code, {}
        except (urllib.error.URLError, OSError) as e:
            sys.exit("Cannot reach the manager at %s (%s)" % (self.server, getattr(e, "reason", e)))


CACHE = ".fake-dns-keys.json"      # keys of the test agents, so the next run can reuse them


def get_keys(m, names, admin_key, key):
    if key:
        return {n: key for n in names}
    try:
        with open(CACHE) as f:
            cache = json.load(f)
    except (OSError, ValueError):
        cache = {}
    mine = cache.setdefault(m.server, {})
    keys = {}
    for n in names:
        if n in mine:
            keys[n] = mine[n]
            continue
        st, d = m.call("POST", "/api/v1/admin/agents", {"name": n, "os": OS.get(n, "")}, {"X-Admin-Key": admin_key})
        if st in (200, 201):
            keys[n] = mine[n] = d["api_key"]
        elif st == 401:
            sys.exit("The admin key was refused. Use the DNSHOLLOW_ADMIN_KEY the manager was started with.")
        elif st == 409 or "exist" in json.dumps(d).lower():
            sys.exit("The test agent '%s' already exists and its key was not saved here.\n"
                     "Delete it on the Agents page and run again (or pass an agent key with --key)." % n)
        else:
            sys.exit("Could not create agent %s: HTTP %s %s" % (n, st, d))
    with open(CACHE, "w") as f:
        json.dump(cache, f)
    try:
        import os
        os.chmod(CACHE, 0o600)
    except OSError:
        pass
    return keys


def send(m, api_key, name, level, rows):
    rows = sorted(rows, key=lambda q: q.ts)
    sent = dropped = 0
    for i in range(0, len(rows), 1000):                 # the manager accepts up to 5000 per batch
        chunk = rows[i:i + 1000]
        st, d = m.call("POST", "/api/v1/agent/ingest",
                       {"batch_id": uuid.uuid4().hex, "os": OS.get(name, "fake"), "agent_version": "fake-0.1",
                        "queries": [q.as_dict() for q in chunk]}, {"X-API-Key": api_key})
        if st == 429:
            time.sleep(11)
            st, d = m.call("POST", "/api/v1/agent/ingest",
                           {"batch_id": uuid.uuid4().hex, "queries": [q.as_dict() for q in chunk]}, {"X-API-Key": api_key})
        if st != 200:
            sys.exit("Manager refused the data: HTTP %s %s" % (st, d))
        sent += d.get("accepted", 0)
        dropped += d.get("dropped", 0) + d.get("ignored_trusted", 0)
    print("  %-11s %-9s %4d queries sent%s" % (name, level, sent, (" (%d dropped/ignored)" % dropped) if dropped else ""))


def main():
    ap = argparse.ArgumentParser(description="Send fake DNS traffic to DNSHollow", epilog=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("level", nargs="?", default="all", choices=sorted(PLAN), help="what to send (default: all)")
    ap.add_argument("--server", default="http://127.0.0.1:8000", help="manager address")
    ap.add_argument("--admin-key", default="", help="admin key: creates the test agents for you")
    ap.add_argument("--key", default="", help="an existing agent key (instead of --admin-key)")
    ap.add_argument("--loop", type=int, default=0, metavar="SEC", help="send fresh traffic every SEC seconds (Ctrl+C to stop)")
    ap.add_argument("--insecure", action="store_true", help="accept a self-signed HTTPS certificate")
    ap.add_argument("--seed", type=int, default=None, help="repeatable data")
    ap.add_argument("--dry-run", action="store_true", help="only print what would be sent")
    a = ap.parse_args()
    if not a.dry_run and not (a.admin_key or a.key):
        ap.error("give --admin-key (creates the test agents) or --key (one existing agent key)")

    plan = PLAN[a.level]
    m = Manager(a.server, a.insecure)
    keys = {} if a.dry_run else get_keys(m, sorted({n for n, _ in plan}), a.admin_key, a.key)
    rng = random.Random(a.seed)
    rounds = 0
    try:
        while True:
            now = time.time()
            print("[%s] sending to %s" % (time.strftime("%H:%M:%S"), a.server))
            for name, level in plan:
                if rounds and level == "slow":
                    continue                                  # the 22 h history only needs sending once
                rows = LEVELS[level](rng, now)
                if a.dry_run:
                    print("  %-11s %-9s %4d queries, e.g. %s" % (name, level, len(rows), rows[0].qname))
                else:
                    send(m, keys[name], name, level, rows)
            rounds += 1
            if a.dry_run or not a.loop:
                break
            time.sleep(a.loop)
    except KeyboardInterrupt:
        print("\nstopped")
        return
    if not a.dry_run:
        print("\nNow open the dashboard. The engine looks every 30 s (slow profile: every 5 min).\n"
              "  benign   -> nothing        low -> Low        medium -> Medium      high -> High\n"
              "  critical -> High, score 90+ (auto-block level)     campaign -> a Campaign card\n"
              "Alerts from the 5-minute window fade after ~5 min; use --loop 120 to keep them alive.")


if __name__ == "__main__":
    main()
