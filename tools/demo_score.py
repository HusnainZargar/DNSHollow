"""Run:  python -m tools.demo_score
Fake traffic -> features -> score. Change SETTINGS to see the score move."""
import random
import string

from manager.engine.features import Query, extract_features, group_queries
from manager.engine.scorer import get_profile, score_features

# Same shape the dashboard will save. Empty dict = all defaults.
SETTINGS = {
    # "profiles": {"fast": {"weights": {"entropy": 0.30}}},
    # "profiles": {"fast": {"ramps": {"entropy": (3.5, 4.5)}}},
    # "trusted_domains": ["google.com"],
}

rng = random.Random(7)
rand = lambda n: "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))

queries = [Query(1000 + i, "pc-tunnel", f"{rand(30)}.{rand(18)}.c2.evil-dns.xyz", "TXT") for i in range(300)]
names = ["www.google.com", "mail.google.com", "docs.google.com"]
queries += [Query(1000 + i * 3.7 + rng.random() * 4, "pc-normal", rng.choice(names), "A") for i in range(80)]

for (host, parent), qs in group_queries(queries, 300, now=1300, min_queries=10).items():
    f = extract_features(qs, parent, trusted_domains=SETTINGS.get("trusted_domains", []))
    r = score_features(f, get_profile(SETTINGS, "fast"))
    print(f"\n{host} -> {parent}: score {r.score} [{r.severity.upper()}] {r.note}")
    for x in r.signals:
        print(f"   {x.points:5.1f} pts  {x.detail}")
