"""Feature engine: raw DNS queries in -> the 7 indicator values out.

Pure functions. No database, no network, no hidden constants:
every tunable value is a function argument, so the dashboard
settings can be passed straight in.

This file only MEASURES. Turning values into scores (ramps, weights)
is the job of scorer.py.
"""
from __future__ import annotations

import math
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from typing import Iterable, Optional

from .domain import is_trusted, split_domain


@dataclass(frozen=True)
class Query:
    ts: float    # unix time (seconds)
    host: str    # agent / host id
    qname: str   # queried name
    qtype: str   # "A", "TXT", "NULL", ...


@dataclass
class Features:
    parent: str
    query_count: int
    entropy: float                       # avg Shannon entropy (bits) of unique subdomains
    depth: float                         # avg subdomain labels per unique name
    abnormal_ratio: float                # share of abnormal record types (0..1)
    qpm: float                           # queries per minute
    timing_cv: Optional[float]           # None = not enough data
    unique_subdomains: int
    data_volume: int                     # characters of subdomain data sent (unique names)
    trusted: bool

    def to_dict(self) -> dict:
        return asdict(self)


# ---------- single-signal functions ----------

def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


def entropy_feature(subdomains: Iterable[str]) -> float:
    """Average entropy of unique subdomains (dots removed). Empty -> 0."""
    values = [shannon_entropy(s.replace(".", "")) for s in set(subdomains) if s]
    return statistics.fmean(values) if values else 0.0


def depth_feature(depths: Iterable[int]) -> float:
    d = list(depths)
    return statistics.fmean(d) if d else 0.0


def abnormal_ratio(qtypes: Iterable[str], abnormal_types: Iterable[str]) -> float:
    """Share of queries whose type is in abnormal_types (e.g. TXT, NULL)."""
    abnormal = {t.upper() for t in abnormal_types}
    types = [t.upper() for t in qtypes]
    if not types:
        return 0.0
    return sum(t in abnormal for t in types) / len(types)


def queries_per_minute(timestamps: list[float], min_span: float = 60.0) -> float:
    """Query rate. Span is floored at min_span so a tiny burst of 5 queries
    in 0.1 s does not produce a silly rate."""
    if not timestamps:
        return 0.0
    span = max(max(timestamps) - min(timestamps), min_span)
    return len(timestamps) / (span / 60.0)


def timing_cv(timestamps: list[float], min_samples: int = 8) -> Optional[float]:
    """Coefficient of variation (std / mean) of gaps between queries.
    Low value = machine-like beaconing. None if too few queries."""
    ts = sorted(timestamps)
    if len(ts) < min_samples:
        return None
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    mean = statistics.fmean(gaps)
    if mean <= 0:
        return None
    return statistics.pstdev(gaps) / mean


def dedupe_close_repeats(queries: list[Query], gap: float = 1.0) -> list[Query]:
    """Drop the same name asked again within `gap` seconds (A+AAAA pairs,
    retries). Repeats further apart are kept, because beacons repeat names."""
    last_seen: dict[str, float] = {}
    out = []
    for q in sorted(queries, key=lambda x: x.ts):
        prev = last_seen.get(q.qname)
        if prev is None or q.ts - prev > gap:
            out.append(q)
            last_seen[q.qname] = q.ts
    return out


def unique_subdomain_count(subdomains: Iterable[str]) -> int:
    return len({s for s in subdomains if s})


def data_volume_feature(subdomains: Iterable[str]) -> int:
    """Total characters of subdomain data carried by unique names (dots not
    counted). A tunnel must send bytes, even if it sends them slowly."""
    return sum(len(s.replace(".", "")) for s in set(subdomains) if s)


# ---------- combine ----------

def extract_features(
    queries: list[Query],
    parent: str,
    *,
    abnormal_types: Iterable[str] = ("TXT", "NULL", "CNAME", "MX"),
    trusted_domains: Iterable[str] = (),
    min_timing_samples: int = 8,
    min_span: float = 60.0,
    dedupe_gap: float = 1.0,
) -> Features:
    """Compute all 7 indicators for one (host, parent domain) group."""
    names = [split_domain(q.qname) for q in queries]
    unique_names = list({n.qname: n for n in names}.values())
    subs = [n.subdomain for n in unique_names]

    timing_queries = dedupe_close_repeats(queries, dedupe_gap)

    return Features(
        parent=parent,
        query_count=len(queries),
        entropy=entropy_feature(subs),
        depth=depth_feature(n.depth for n in unique_names),
        abnormal_ratio=abnormal_ratio((q.qtype for q in queries), abnormal_types),
        qpm=queries_per_minute([q.ts for q in queries], min_span),
        timing_cv=timing_cv([q.ts for q in timing_queries], min_timing_samples),
        unique_subdomains=unique_subdomain_count(subs),
        data_volume=data_volume_feature(subs),
        trusted=is_trusted(parent, trusted_domains),
    )


def group_queries(
    queries: Iterable[Query],
    window_seconds: float,
    now: Optional[float] = None,
    min_queries: int = 1,
) -> dict[tuple[str, str], list[Query]]:
    """Group queries by (host, parent domain) inside the sliding window
    [now - window_seconds, now]. Groups smaller than min_queries are dropped."""
    now = time.time() if now is None else now
    start = now - window_seconds
    groups: dict[tuple[str, str], list[Query]] = defaultdict(list)
    for q in queries:
        if start <= q.ts <= now:
            parent = split_domain(q.qname).parent
            if parent:
                groups[(q.host, parent)].append(q)
    return {k: v for k, v in groups.items() if len(v) >= min_queries}
