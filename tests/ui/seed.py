import json, random, string, time, urllib.request
BASE = "http://127.0.0.1:8790/api/v1"; H = {"X-Admin-Key": "k", "Content-Type": "application/json"}
def call(m, p, body=None, key=None):
    h = {"X-API-Key": key, "Content-Type": "application/json"} if key else H
    r = urllib.request.Request(BASE + p, method=m, data=json.dumps(body).encode() if body is not None else None, headers=h)
    return json.loads(urllib.request.urlopen(r).read())
rng = random.Random(5); rand = lambda n: "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))
a = call("POST", "/admin/agents", {"name": "lab-pc", "os": "linux"}); call("POST", "/admin/agents", {"name": "old-server"})
now = time.time(); rows = []
for i in range(280):
    pre = "<img src=x onerror=alert(1)>." if i >= 250 else ""
    rows.append({"ts": now - 290 + i, "qname": "%s%s.%s.c2.evil-dns.xyz" % (pre, rand(30), rand(18)), "qtype": "TXT",
                 "resolver": "8.8.8.8", "proto": "udp", "qbytes": 72, "rbytes": 130, "rcode": 3})
for i in range(60):
    rows.append({"ts": now - 22 * 3600 + i * 1300 * rng.uniform(.97, 1.03), "qname": "%s.stealth-c2.net" % rand(40), "qtype": "TXT", "resolver": "9.9.9.9", "proto": "udp", "qbytes": 80, "rbytes": 100, "rcode": 0})
for i in range(40):
    rows.append({"ts": now - 600 + i * 12, "qname": "www.shop.com", "qtype": "A", "resolver": "192.168.1.1", "proto": "udp", "qbytes": 40, "rbytes": 90, "rcode": 0})
print(call("POST", "/agent/ingest", {"batch_id": "seed1", "os": "Linux 6.1", "agent_version": "0.1.0", "queries": rows}, key=a["api_key"]))
print(call("POST", "/admin/run/fast"), call("POST", "/admin/run/slow"))
