"""Engine runner: reads stored queries, scores each (host, domain) group,
and writes alerts. Called by the scheduler every few seconds (24/7) or
manually through the API.

group_queries (SQL) -> extract_features -> score_features -> upsert_alert
"""
from __future__ import annotations

import time
from typing import Optional

from ..db import Database
from .blocking import auto_block
from .domain import is_trusted
from .features import Query, extract_features
from .scorer import get_profile, score_features


def run_profile(db: Database, settings: dict, name: str,
                now: Optional[float] = None) -> dict:
    """Score one profile ("fast" or "slow"). Returns run statistics."""
    now = time.time() if now is None else now
    prof = get_profile(settings, name)
    stats = {"profile": name, "groups": 0, "scored": 0,
             "created": 0, "updated": 0, "suppressed": 0, "expired": 0, "blocked": 0}
    if not prof["enabled"]:
        stats["skipped"] = "profile disabled"
        return stats

    trusted = settings["trusted_domains"]
    abnormal = settings["abnormal_types"]
    since = now - prof["window_seconds"]

    for host, parent, _count in db.candidate_groups(since, now, prof["min_queries"]):
        stats["groups"] += 1
        if is_trusted(parent, trusted):
            continue
        rows = db.fetch_group(host, parent, since, now)
        queries = [Query(ts, host, qn, qt) for ts, qn, qt in rows]
        feats = extract_features(
            queries, parent,
            abnormal_types=abnormal, trusted_domains=trusted,
            min_timing_samples=prof["min_timing_samples"])
        result = score_features(feats, prof)
        stats["scored"] += 1
        if result.severity == "none":
            continue
        alert_id, action = db.upsert_alert(
            name, host, parent, result.score, result.severity, result.summary,
            [s for s in result.to_dict()["signals"]], now)
        stats[action] += 1
        if action != "suppressed" and auto_block(db, settings, host=host, parent=parent,
                                                 score=result.score, alert_id=alert_id, now=now):
            stats["blocked"] += 1

    # An alert that has not fired for 2 windows (min 10 min) is expired.
    idle = max(2 * prof["window_seconds"], 600)
    stats["expired"] = db.expire_alerts(name, now - idle)
    db.expire_blocks(now)                                  # timed blocks end by themselves
    return stats


def purge_old(db: Database, settings: dict, now: Optional[float] = None) -> int:
    now = time.time() if now is None else now
    return db.purge(now - settings["retention_days"] * 86400)
