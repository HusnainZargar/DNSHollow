"""Run:  python -m tools.demo_features
Prints the 7 indicator values for a fake tunnel and for normal traffic."""
import json
import random
import string

from manager.engine.features import Query, extract_features, group_queries

rng = random.Random(7)
rand = lambda n: "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))

queries = []
# 1) tunnel: beacon every 1 s, random labels, TXT records, new domain
queries += [Query(1000 + i, "pc-tunnel", f"{rand(30)}.{rand(18)}.c2.evil-dns.xyz", "TXT") for i in range(300)]
# 2) normal browsing
names = ["www.google.com", "mail.google.com", "docs.google.com", "fonts.gstatic.com"]
queries += [Query(1000 + i * 3.7 + rng.random() * 4, "pc-normal", rng.choice(names), "A") for i in range(80)]

groups = group_queries(queries, window_seconds=300, now=1300, min_queries=10)
for (host, parent), qs in groups.items():
    f = extract_features(qs, parent, trusted_domains=["google.com"])
    print(f"\n{host} -> {parent}")
    print(json.dumps(f.to_dict(), indent=2, default=str))
