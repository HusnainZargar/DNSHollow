import copy
import json

import pytest

from manager.engine.features import Features
from manager.engine.scorer import (
    SIGNALS, get_profile, merge_profile, ramp, score_features,
    severity_for, signal_strengths, validate_settings,
)
from manager.engine.settings import DEFAULTS, merge_settings

FAST = DEFAULTS["profiles"]["fast"]
SLOW = DEFAULTS["profiles"]["slow"]


def feats(**kw):
    base = dict(parent="evil.com", query_count=300, entropy=4.8, depth=3.2,
                abnormal_ratio=0.4, qpm=60.0, timing_cv=0.05,
                unique_subdomains=290, data_volume=12000, trusted=False)
    base.update(kw)
    return Features(**base)


def calm(**kw):
    base = dict(parent="site.com", query_count=60, entropy=1.3, depth=1.0,
                abnormal_ratio=0.0, qpm=5.0, timing_cv=0.6,
                unique_subdomains=3, data_volume=100, trusted=False)
    base.update(kw)
    return Features(**base)


def stealth(**kw):
    """Slow tunnel: 60 queries in 22 h, jittered beacon."""
    base = dict(parent="stealth.net", query_count=60, entropy=4.9, depth=2.0,
                abnormal_ratio=0.6, qpm=0.045, timing_cv=0.06,
                unique_subdomains=60, data_volume=2700, trusted=False)
    base.update(kw)
    return Features(**base)


def test_weights_sum_to_one():
    for p in (FAST, SLOW):
        assert sum(p["weights"].values()) == pytest.approx(1.0)
        assert set(p["weights"]) == set(SIGNALS)
        assert set(p["ramps"]) == set(SIGNALS)


# ---- ramp ----
def test_ramp_forward():
    assert ramp(3.0, 3.0, 4.5) == 0.0
    assert ramp(3.75, 3.0, 4.5) == pytest.approx(0.5)
    assert ramp(4.5, 3.0, 4.5) == 1.0


def test_ramp_clamps():
    assert ramp(1, 3.0, 4.5) == 0.0
    assert ramp(9, 3.0, 4.5) == 1.0


def test_ramp_reversed_direction():
    assert ramp(0.5, 0.5, 0.1) == 0.0
    assert ramp(0.3, 0.5, 0.1) == pytest.approx(0.5)
    assert ramp(0.05, 0.5, 0.1) == 1.0


def test_ramp_equal_thresholds_is_zero():
    assert ramp(5, 2, 2) == 0.0


# ---- strengths ----
def test_strengths_tunnel():
    s = signal_strengths(feats(), FAST["ramps"])
    assert s["entropy"] == 1.0
    assert s["depth"] == pytest.approx(0.6)
    assert s["record_types"] == 1.0
    assert s["frequency"] == 1.0
    assert s["timing"] == 1.0
    assert s["unique_subdomains"] == 1.0
    assert s["data_volume"] == 1.0


def test_timing_none_is_zero():
    assert signal_strengths(feats(timing_cv=None), FAST["ramps"])["timing"] == 0.0


# ---- fast profile scores ----
def test_tunnel_scores_96_high():
    r = score_features(feats(), FAST)
    assert r.score == pytest.approx(96.0)
    assert r.severity == "high"
    assert r.firing == 7          # all 7 signals are >= 0.5


def test_calm_scores_zero():
    r = score_features(calm(), FAST)
    assert r.score == 0.0 and r.severity == "none"


def test_default_profile_is_fast():
    assert score_features(feats()).score == score_features(feats(), FAST).score


def test_partial_signals_give_partial_score():
    r = score_features(calm(entropy=4.8, abnormal_ratio=0.4), FAST)
    assert r.score == pytest.approx(35.0)      # 20 + 15
    assert r.severity == "none"                # below low=40


# ---- slow profile catches stealth ----
def test_stealth_tunnel_is_high_on_slow_profile():
    r = score_features(stealth(), SLOW)
    assert r.severity == "high"
    assert r.score >= 80


def test_stealth_tunnel_is_missed_by_fast_profile_numbers():
    """Same data judged with fast thresholds: low rate and few uniques,
    so it does not reach an alert. This is why the slow profile exists."""
    r = score_features(stealth(), FAST)
    assert r.severity in ("none", "low")


def test_calm_traffic_over_24h_stays_quiet_on_slow():
    r = score_features(calm(query_count=200, qpm=0.14, data_volume=250,
                            unique_subdomains=4, timing_cv=1.2), SLOW)
    assert r.severity == "none"


# ---- gates ----
def test_trusted_is_not_scored():
    r = score_features(feats(trusted=True), FAST)
    assert r.score == 0.0 and r.severity == "none" and "Trusted" in r.note


def test_too_few_queries_is_not_scored():
    r = score_features(feats(query_count=5), FAST)
    assert r.score == 0.0 and "minimum" in r.note


def test_min_signals_gate():
    prof = {"severity": {"low": 1, "medium": 2, "high": 3}, "min_signals": 2}
    r = score_features(calm(entropy=4.8), prof)    # only entropy fires
    assert r.score == 20.0 and r.severity == "none" and "need 2" in r.note
    prof["min_signals"] = 1
    assert score_features(calm(entropy=4.8), prof).severity == "high"


# ---- settings drive the result ----
def test_weights_are_normalized():
    p2 = {"weights": {k: v * 2 for k, v in FAST["weights"].items()}}
    assert score_features(feats(), p2).score == score_features(feats()).score


def test_zero_weight_removes_signal():
    r = score_features(feats(), {"weights": {"entropy": 0}})
    assert {x.name: x for x in r.signals}["entropy"].points == 0
    assert r.score == pytest.approx(100 * (0.96 - 0.20) / 0.80, abs=0.1)


def test_all_weights_zero():
    r = score_features(feats(), {"weights": {k: 0 for k in SIGNALS}})
    assert r.score == 0.0 and "weights" in r.note.lower()


def test_changing_ramp_changes_score():
    f = feats(entropy=4.0)
    assert (score_features(f, {"ramps": {"entropy": (2.0, 3.0)}}).score
            > score_features(f, {"ramps": {"entropy": (5.0, 6.0)}}).score)


def test_changing_severity_bands():
    r = score_features(feats(), {"severity": {"high": 99}})
    assert r.score == 96.0 and r.severity == "medium"


def test_settings_survive_json_roundtrip():
    stored = json.loads(json.dumps(DEFAULTS))
    prof = get_profile(stored, "slow")
    assert score_features(stealth(), prof).severity == "high"


def test_defaults_not_mutated():
    before = copy.deepcopy(DEFAULTS)
    score_features(feats(), {"weights": {"entropy": 0.9}, "severity": {"high": 10}})
    merge_settings({"profiles": {"fast": {"weights": {"entropy": 0.9}}}})
    merge_profile({"weights": {"entropy": 0.9}})
    assert DEFAULTS == before


# ---- severity ----
def test_severity_bands_edges():
    b = FAST["severity"]
    assert severity_for(39.9, b) == "none"
    assert severity_for(40, b) == "low"
    assert severity_for(60, b) == "medium"
    assert severity_for(80, b) == "high"


# ---- evidence ----
def test_evidence_sorted_and_explained():
    r = score_features(feats(), FAST)
    pts = [x.points for x in r.signals]
    assert pts == sorted(pts, reverse=True)
    assert len(r.signals) == 7
    assert r.signals[0].name == "entropy"
    assert "Entropy 4.80 bits" in r.summary
    assert "Abnormal record types 40%" in r.summary
    assert "chars of subdomain data" in r.summary
    assert sum(x.points for x in r.signals) == pytest.approx(r.score, abs=0.5)


def test_to_dict_is_json_ready():
    json.dumps(score_features(feats(), FAST).to_dict())


# ---- validate / merge ----
def test_validate_defaults_ok():
    assert validate_settings(DEFAULTS) == []


def test_validate_catches_bad_values():
    assert validate_settings({"profiles": {"fast": {"weights": {"entropy": -1}}}})
    assert validate_settings({"profiles": {"fast": {"ramps": {"entropy": (3, 3)}}}})
    assert validate_settings({"profiles": {"fast": {"severity": {"low": 70, "medium": 60, "high": 80}}}})
    assert validate_settings({"profiles": {"slow": {"weights": {k: 0 for k in SIGNALS}}}})
    assert validate_settings({"profiles": {"fast": {"window_seconds": 0}}})
    assert validate_settings({"profiles": {"fast": {"min_signals": 9}}})
    assert validate_settings({"retention_days": 0})
    assert validate_settings({"retention_days": 1, "profiles": {"slow": {"window_seconds": 200000}}})
    assert validate_settings({"campaign_min_hosts": 1})
    assert validate_settings({"agent": {"max_batch_size": 0}})
    assert validate_settings({"trusted_domains": "google.com"})


def test_merge_partial_profile():
    m = merge_settings({"profiles": {"slow": {"weights": {"entropy": 0.5}}}})
    assert m["profiles"]["slow"]["weights"]["entropy"] == 0.5
    assert m["profiles"]["slow"]["weights"]["depth"] == SLOW["weights"]["depth"]
    assert m["profiles"]["fast"] == FAST
