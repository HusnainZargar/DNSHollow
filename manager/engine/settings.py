"""Default settings. Stored in the DB (`settings` table) on first save.
After that, the dashboard / admin API is the only place they are edited.

Two detection profiles run on the same engine:
  fast: short window, catches noisy tunnels (iodine, dnscat2 ...)
  slow: 24 h window, catches stealthy tunnels that send few queries
"""
import copy

_SEVERITY = {"low": 40, "medium": 60, "high": 80}

DEFAULTS = {
    "trusted_domains": [],                       # skipped completely
    "abnormal_types": ["TXT", "NULL", "CNAME", "MX"],
    "retention_days": 7,                         # raw query history kept
    "campaign_min_hosts": 2,                     # hosts hitting one domain = campaign
    "agent": {
        "batch_interval_seconds": 10,
        "max_batch_size": 5000,
        "max_batches_per_minute": 30,            # per agent
    },
    # Blocking: agents drop DNS for a blocked domain (only agents installed with blocking enabled).
    "blocking": {
        "enabled": True,                         # master switch. Off = nothing is blocked anywhere
        "auto_block": False,                     # block by itself when a score reaches auto_min_score
        "auto_min_score": 90,                    # 0-100, same scale as the alert score
        "auto_scope": "host",                    # "host" = only the computer that raised the alert, "all" = every computer
        "auto_expire_hours": 24,                 # 0 = stays until someone unblocks it
    },
    "profiles": {
        "fast": {
            "enabled": True,
            "window_seconds": 300,
            "run_every_seconds": 30,
            "min_queries": 10,
            "min_timing_samples": 8,
            "min_signals": 2,                    # signals >= 0.5 needed to alert
            "weights": {
                "entropy": 0.20, "depth": 0.10, "record_types": 0.15,
                "frequency": 0.15, "timing": 0.15,
                "unique_subdomains": 0.15, "data_volume": 0.10,
            },
            # signal: (strength 0 at, strength 1 at)
            "ramps": {
                "entropy": (3.0, 4.5), "depth": (2, 4),
                "record_types": (0.05, 0.30), "frequency": (10, 50),
                "timing": (0.5, 0.1), "unique_subdomains": (20, 200),
                "data_volume": (500, 5000),
            },
            "severity": dict(_SEVERITY),
        },
        "slow": {
            "enabled": True,
            "window_seconds": 86400,
            "run_every_seconds": 300,
            "min_queries": 8,
            "min_timing_samples": 8,
            "min_signals": 3,
            "weights": {
                "entropy": 0.25, "depth": 0.10, "record_types": 0.15,
                "frequency": 0.05, "timing": 0.15,
                "unique_subdomains": 0.10, "data_volume": 0.20,
            },
            "ramps": {
                "entropy": (3.0, 4.5), "depth": (2, 4),
                "record_types": (0.05, 0.30), "frequency": (0.05, 0.5),
                "timing": (0.6, 0.15), "unique_subdomains": (10, 60),
                "data_volume": (300, 3000),
            },
            "severity": dict(_SEVERITY),
        },
    },
}


# One-click sensitivity. Presets only move the alert levels and the number of
# high signals needed. Weights and thresholds are left alone.
PRESETS = {
    "relaxed": {"profiles": {
        "fast": {"severity": {"low": 50, "medium": 70, "high": 90}, "min_signals": 3},
        "slow": {"severity": {"low": 50, "medium": 70, "high": 90}, "min_signals": 4}}},
    "balanced": {"profiles": {
        "fast": {"severity": dict(_SEVERITY), "min_signals": 2},
        "slow": {"severity": dict(_SEVERITY), "min_signals": 3}}},
    "strict": {"profiles": {
        "fast": {"severity": {"low": 30, "medium": 50, "high": 70}, "min_signals": 2},
        "slow": {"severity": {"low": 30, "medium": 50, "high": 70}, "min_signals": 2}}},
}


def deep_update(base: dict, new: dict) -> dict:
    """Recursively overlay `new` on `base` (in place). Lists/values replace."""
    for k, v in new.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            deep_update(base[k], v)
        else:
            base[k] = copy.deepcopy(v)
    return base


def merge_settings(user: dict | None) -> dict:
    """DEFAULTS overlaid with the user's settings. Missing keys = defaults."""
    return deep_update(copy.deepcopy(DEFAULTS), user or {})


# One-click sensitivity levels (the dashboard "Settings" page). They only change
# how many strong signals are needed and where the severity lines are.
PRESETS = {
    "relaxed": {
        "title": "Relaxed",
        "description": "Fewer alerts. Best for busy, noisy networks. Weak tunnels may be missed.",
        "config": {"profiles": {
            "fast": {"min_signals": 3, "severity": {"low": 50, "medium": 70, "high": 90}},
            "slow": {"min_signals": 4, "severity": {"low": 50, "medium": 70, "high": 90}}}},
    },
    "balanced": {
        "title": "Balanced",
        "description": "Recommended. A good mix of catching real tunnels and avoiding false alarms.",
        "config": {"profiles": {
            "fast": {"min_signals": 2, "severity": {"low": 40, "medium": 60, "high": 80}},
            "slow": {"min_signals": 3, "severity": {"low": 40, "medium": 60, "high": 80}}}},
    },
    "strict": {
        "title": "Strict",
        "description": "More alerts. Catches weaker tunnels, but expect more false alarms to review.",
        "config": {"profiles": {
            "fast": {"min_signals": 2, "severity": {"low": 30, "medium": 50, "high": 70}},
            "slow": {"min_signals": 2, "severity": {"low": 30, "medium": 50, "high": 70}}}},
    },
}
