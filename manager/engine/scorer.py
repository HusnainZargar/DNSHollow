"""Scoring engine: Features in -> score (0-100), severity and evidence out.

Steps:
  1. each indicator value -> strength 0..1 (linear ramp between two thresholds)
  2. score = 100 * sum(weight_share * strength)   (weights are auto-normalized)
  3. severity from the score bands
  4. "min_signals" gate: need N signals with strength >= 0.5 to alert
  5. evidence = every signal with its value and points contributed

Pure functions. All numbers come from a *profile* settings dict (fast or
slow). Missing keys fall back to the default fast profile.
"""
from __future__ import annotations

import copy
from dataclasses import asdict, dataclass, field
from typing import Optional

from .features import Features
from .settings import DEFAULTS, deep_update, merge_settings

SIGNALS = (
    "entropy", "depth", "record_types", "frequency",
    "timing", "unique_subdomains", "data_volume",
)

LABELS = {
    "entropy": "High entropy",
    "depth": "Deep subdomains",
    "record_types": "Abnormal record types",
    "frequency": "High query rate",
    "timing": "Regular timing (beaconing)",
    "unique_subdomains": "Many unique subdomains",
    "data_volume": "Data volume in subdomains",
}

FIRING_STRENGTH = 0.5   # a signal counts as "high" at or above this


# ---------- settings helpers ----------

def merge_profile(partial: Optional[dict]) -> dict:
    """Overlay a (partial) profile dict on the default fast profile."""
    return deep_update(copy.deepcopy(DEFAULTS["profiles"]["fast"]), partial or {})


def get_profile(settings: dict, name: str) -> dict:
    return merge_settings(settings)["profiles"][name]


def _validate_profile(name: str, p: dict) -> list[str]:
    errors = []
    for sig in SIGNALS:
        w = p["weights"].get(sig)
        if not isinstance(w, (int, float)) or isinstance(w, bool) or w < 0:
            errors.append(f"[{name}] weight for '{sig}' must be a number >= 0.")
        ramp_ = p["ramps"].get(sig)
        if (not isinstance(ramp_, (list, tuple)) or len(ramp_) != 2
                or not all(isinstance(x, (int, float)) for x in ramp_)
                or ramp_[0] == ramp_[1]):
            errors.append(f"[{name}] thresholds for '{sig}' need two different numbers.")
    try:
        if sum(float(p["weights"].get(s, 0)) for s in SIGNALS) <= 0:
            errors.append(f"[{name}] at least one weight must be above 0.")
    except (TypeError, ValueError):
        pass
    sev = p["severity"]
    try:
        if not (0 <= sev["low"] < sev["medium"] < sev["high"] <= 100):
            errors.append(f"[{name}] severity levels must satisfy 0 <= low < medium < high <= 100.")
    except TypeError:
        errors.append(f"[{name}] severity levels must be numbers.")
    if not isinstance(p["window_seconds"], (int, float)) or p["window_seconds"] <= 0:
        errors.append(f"[{name}] window must be greater than 0 seconds.")
    if not isinstance(p["run_every_seconds"], (int, float)) or p["run_every_seconds"] < 5:
        errors.append(f"[{name}] run interval must be at least 5 seconds.")
    if not isinstance(p["min_queries"], int) or p["min_queries"] < 1:
        errors.append(f"[{name}] minimum queries must be at least 1.")
    if not isinstance(p["min_signals"], int) or not (1 <= p["min_signals"] <= len(SIGNALS)):
        errors.append(f"[{name}] minimum signals must be between 1 and {len(SIGNALS)}.")
    return errors


def validate_settings(settings: dict) -> list[str]:
    """Return a list of human-readable problems (empty list = OK).
    The dashboard / API calls this before saving."""
    s = merge_settings(settings)
    errors: list[str] = []

    for name, prof in s["profiles"].items():
        errors += _validate_profile(name, prof)

    if not isinstance(s["trusted_domains"], list) or not all(isinstance(x, str) for x in s["trusted_domains"]):
        errors.append("Trusted domains must be a list of text values.")
    if not isinstance(s["abnormal_types"], list) or not all(isinstance(x, str) for x in s["abnormal_types"]):
        errors.append("Abnormal record types must be a list of text values.")
    if not isinstance(s["retention_days"], (int, float)) or s["retention_days"] < 1:
        errors.append("Retention must be at least 1 day.")
    else:
        longest = max((p["window_seconds"] for p in s["profiles"].values()
                       if p.get("enabled") and isinstance(p["window_seconds"], (int, float))), default=0)
        if s["retention_days"] * 86400 < longest:
            errors.append("Retention is shorter than the longest detection window.")
    if not isinstance(s["campaign_min_hosts"], int) or s["campaign_min_hosts"] < 2:
        errors.append("Campaign minimum hosts must be at least 2.")
    a = s["agent"]
    if not isinstance(a["batch_interval_seconds"], (int, float)) or a["batch_interval_seconds"] < 1:
        errors.append("Agent batch interval must be at least 1 second.")
    if not isinstance(a["max_batch_size"], int) or not (1 <= a["max_batch_size"] <= 20000):
        errors.append("Agent max batch size must be between 1 and 20000.")
    if not isinstance(a["max_batches_per_minute"], int) or a["max_batches_per_minute"] < 1:
        errors.append("Agent max batches per minute must be at least 1.")
    b = s["blocking"]
    if not isinstance(b, dict):
        return errors + ["Blocking settings must be an object."]
    for key in ("enabled", "auto_block"):
        if not isinstance(b.get(key), bool):
            errors.append(f"Blocking: '{key}' must be on or off.")
    sc = b.get("auto_min_score")
    if not isinstance(sc, (int, float)) or isinstance(sc, bool) or not (1 <= sc <= 100):
        errors.append("Auto-block score must be a number from 1 to 100.")
    if b.get("auto_scope") not in ("host", "all"):
        errors.append("Auto-block scope must be 'host' or 'all'.")
    hrs = b.get("auto_expire_hours")
    if not isinstance(hrs, (int, float)) or isinstance(hrs, bool) or not (0 <= hrs <= 24 * 365):
        errors.append("Auto-block duration must be 0 (until removed) or up to 8760 hours.")
    return errors


# ---------- core math ----------

def ramp(value: float, zero_at: float, full_at: float) -> float:
    """Linear 0..1. Strength is 0 at `zero_at`, 1 at `full_at`, clamped.
    Works in both directions (e.g. low timing CV = high strength)."""
    if zero_at == full_at:
        return 0.0
    s = (value - zero_at) / (full_at - zero_at)
    return max(0.0, min(1.0, s))


def signal_strengths(f: Features, ramps: dict) -> dict[str, float]:
    """Strength 0..1 for each of the 7 signals."""
    r = ramps
    return {
        "entropy": ramp(f.entropy, *r["entropy"]),
        "depth": ramp(f.depth, *r["depth"]),
        "record_types": ramp(f.abnormal_ratio, *r["record_types"]),
        "frequency": ramp(f.qpm, *r["frequency"]),
        "timing": 0.0 if f.timing_cv is None else ramp(f.timing_cv, *r["timing"]),
        "unique_subdomains": ramp(f.unique_subdomains, *r["unique_subdomains"]),
        "data_volume": ramp(f.data_volume, *r["data_volume"]),
    }


def severity_for(score: float, bands: dict) -> str:
    if score >= bands["high"]:
        return "high"
    if score >= bands["medium"]:
        return "medium"
    if score >= bands["low"]:
        return "low"
    return "none"


def _describe(name: str, f: Features) -> str:
    """Short evidence text with the real measured value."""
    if name == "entropy":
        return f"Entropy {f.entropy:.2f} bits"
    if name == "depth":
        return f"Subdomain depth {f.depth:.1f}"
    if name == "record_types":
        return f"Abnormal record types {f.abnormal_ratio:.0%}"
    if name == "frequency":
        return f"{f.qpm:.2f} queries/min" if f.qpm < 10 else f"{f.qpm:.0f} queries/min"
    if name == "timing":
        return "Timing CV n/a" if f.timing_cv is None else f"Beacon timing CV {f.timing_cv:.2f}"
    if name == "unique_subdomains":
        return f"{f.unique_subdomains} unique subdomains"
    if name == "data_volume":
        return f"{f.data_volume} chars of subdomain data"
    return name


# ---------- result ----------

@dataclass
class SignalResult:
    name: str
    label: str
    detail: str          # e.g. "Entropy 4.80 bits"
    strength: float      # 0..1
    weight_pct: float    # share of the total weight, in percent
    points: float        # contribution to the final score


@dataclass
class ScoreResult:
    parent: str
    score: float
    severity: str                       # none / low / medium / high
    signals: list[SignalResult] = field(default_factory=list)  # sorted by points, high first
    summary: str = ""
    note: str = ""                      # why scoring was skipped / downgraded
    firing: int = 0                     # how many signals are "high"

    def to_dict(self) -> dict:
        return asdict(self)


# ---------- main entry ----------

def score_features(f: Features, profile: Optional[dict] = None) -> ScoreResult:
    s = merge_profile(profile)

    # Skipped cases: trusted domain, or too few queries to judge.
    if f.trusted:
        return ScoreResult(f.parent, 0.0, "none", note="Trusted domain (not scored)")
    if f.query_count < s["min_queries"]:
        return ScoreResult(
            f.parent, 0.0, "none",
            note=f"Only {f.query_count} queries (minimum {s['min_queries']})",
        )

    strengths = signal_strengths(f, s["ramps"])
    weights = {n: float(s["weights"].get(n, 0)) for n in SIGNALS}
    total_w = sum(weights.values())
    if total_w <= 0:
        return ScoreResult(f.parent, 0.0, "none", note="All weights are 0")

    signals = []
    for name in SIGNALS:
        share = weights[name] / total_w
        signals.append(SignalResult(
            name=name,
            label=LABELS[name],
            detail=_describe(name, f),
            strength=round(strengths[name], 3),
            weight_pct=round(share * 100, 1),
            points=round(100 * share * strengths[name], 1),
        ))
    signals.sort(key=lambda x: x.points, reverse=True)

    score = round(sum(100 * (weights[n] / total_w) * strengths[n] for n in SIGNALS), 1)
    severity = severity_for(score, s["severity"])

    firing_list = [x for x in signals if x.strength >= FIRING_STRENGTH and x.points > 0]
    note = ""
    if severity != "none" and len(firing_list) < s["min_signals"]:
        note = f"Only {len(firing_list)} high signal(s), need {s['min_signals']}"
        severity = "none"

    summary = ", ".join(f"{x.detail} (+{x.points:g})" for x in firing_list)
    return ScoreResult(f.parent, score, severity, signals, summary, note, len(firing_list))
