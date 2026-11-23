"""Fake agent for testing the API. Uses only the standard library.

  python -m tools.simulate_agent --url http://127.0.0.1:8000 --key dh_agent_XXXX --scenario all

Scenarios:
  normal  - ordinary browsing
  fast    - noisy tunnel (last 5 minutes)
  slow    - stealth tunnel (60 queries spread over 22 hours)
  all     - the three above

Then run the engine:  POST /api/v1/admin/run/fast  and  /run/slow
"""
import argparse
import json
import random
import string
import time
import urllib.request
import uuid

rng = random.Random()
rand = lambda n: "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def normal(now):
    names = ["www.shop-example.com", "cdn.shop-example.com", "api.shop-example.com"]
    return [{"ts": now - 80000 + i * 400 + rng.random() * 150, "qname": names[i % 3], "qtype": "A"}
            for i in range(200)]


def fast(now):
    return [{"ts": now - 290 + i, "qname": f"{rand(30)}.{rand(18)}.c2.evil-dns.xyz", "qtype": "TXT"}
            for i in range(280)]


def slow(now):
    rows, t = [], now - 22 * 3600
    for _ in range(60):
        rows.append({"ts": t, "qname": f"{rand(40)}.stealth-c2.net", "qtype": rng.choice(["TXT", "NULL", "TXT"])})
        t += 22 * 60 * rng.uniform(0.95, 1.05)
    return rows


def post(url, key, body):
    req = urllib.request.Request(
        url + "/api/v1/agent/ingest", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "X-API-Key": key})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--key", required=True)
    ap.add_argument("--scenario", choices=["normal", "fast", "slow", "all"], default="all")
    a = ap.parse_args()

    now = time.time()
    chosen = {"normal": [normal], "fast": [fast], "slow": [slow], "all": [normal, fast, slow]}[a.scenario]
    for fn in chosen:
        rows = fn(now)
        print(fn.__name__, post(a.url, a.key, {
            "batch_id": uuid.uuid4().hex, "os": "linux", "agent_version": "sim-0.1", "queries": rows}))


if __name__ == "__main__":
    main()
