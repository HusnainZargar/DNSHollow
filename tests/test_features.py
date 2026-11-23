import random
import string

import pytest

from manager.engine.features import (
    Query, abnormal_ratio, data_volume_feature, dedupe_close_repeats,
    entropy_feature, extract_features, group_queries, queries_per_minute,
    shannon_entropy, timing_cv, unique_subdomain_count,
)


def rand_label(n=32, rng=random.Random(1)):
    return "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))


# ---- entropy ----
def test_entropy_basics():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("ab") == pytest.approx(1.0)


def test_entropy_random_higher_than_words():
    assert entropy_feature([rand_label() for _ in range(20)]) > 4.0
    assert entropy_feature(["www", "mail", "api", "cdn"]) < 2.5


def test_entropy_ignores_repeats_and_empty():
    assert entropy_feature(["", "www", "www"]) == entropy_feature(["www"])


# ---- record types ----
def test_abnormal_ratio():
    assert abnormal_ratio(["A", "TXT", "AAAA", "NULL"], ["TXT", "NULL"]) == 0.5
    assert abnormal_ratio(["txt"], ["TXT"]) == 1.0      # case-insensitive
    assert abnormal_ratio([], ["TXT"]) == 0.0


def test_abnormal_ratio_uses_given_settings():
    assert abnormal_ratio(["A", "MX"], ["TXT"]) == 0.0   # MX not abnormal here


# ---- frequency ----
def test_qpm():
    # 60 queries over 60 s -> 60/min
    assert queries_per_minute([i * (60 / 59) for i in range(60)]) == pytest.approx(60.0, rel=0.01)


def test_qpm_burst_is_floored():
    assert queries_per_minute([0, 0.1, 0.2, 0.3, 0.4]) == pytest.approx(5.0)


# ---- timing ----
def test_timing_perfect_beacon():
    assert timing_cv([i * 5.0 for i in range(20)]) == pytest.approx(0.0, abs=1e-9)


def test_timing_random_is_high():
    rng = random.Random(2)
    t, ts = 0.0, []
    for _ in range(50):
        t += rng.expovariate(1 / 5)
        ts.append(t)
    assert timing_cv(ts) > 0.5


def test_timing_not_enough_data():
    assert timing_cv([0, 5, 10]) is None


def test_dedupe_close_repeats_keeps_beacon_repeats():
    qs = [Query(0.0, "h", "a.com", "A"), Query(0.2, "h", "a.com", "AAAA"),
          Query(5.0, "h", "a.com", "A")]
    assert len(dedupe_close_repeats(qs, gap=1.0)) == 2


# ---- unique subdomains ----
def test_unique_subdomain_count():
    assert unique_subdomain_count(["a", "b", "a", ""]) == 2


# ---- data volume ----
def test_data_volume_counts_unique_chars_without_dots():
    assert data_volume_feature(["abc.de", "abc.de", "xyz", ""]) == 5 + 3


# ---- full extraction: tunnel vs normal ----
def make_tunnel(n=300):
    return [Query(i * 1.0, "pc1", f"{rand_label()}.{rand_label(20)}.x.evil.com", "TXT")
            for i in range(n)]


def make_normal(n=60):
    names = ["www.google.com", "mail.google.com", "www.google.com", "docs.google.com"]
    return [Query(i * 4.3 + (i % 7) * 0.9, "pc1", names[i % 4], "A" if i % 5 else "AAAA")
            for i in range(n)]


def test_tunnel_features_look_like_tunnel():
    f = extract_features(make_tunnel(), "evil.com")
    assert f.entropy > 4.0
    assert f.depth == 3
    assert f.abnormal_ratio == 1.0
    assert f.qpm >= 55
    assert f.timing_cv < 0.05
    assert f.unique_subdomains == 300
    assert f.data_volume > 10000


def test_normal_features_look_normal():
    f = extract_features(make_normal(), "google.com", trusted_domains=["google.com"])
    assert f.entropy < 3.0
    assert f.depth == 1
    assert f.abnormal_ratio == 0.0
    assert f.unique_subdomains <= 3
    assert f.data_volume < 100
    assert f.trusted is True


# ---- grouping ----
def test_group_queries_window_and_min():
    qs = [Query(100, "h1", "a.evil.com", "A"), Query(101, "h1", "b.evil.com", "A"),
          Query(102, "h2", "a.evil.com", "A"),
          Query(10, "h1", "old.evil.com", "A")]            # outside window
    g = group_queries(qs, window_seconds=60, now=110, min_queries=1)
    assert set(g) == {("h1", "evil.com"), ("h2", "evil.com")}
    assert len(g[("h1", "evil.com")]) == 2
    assert group_queries(qs, 60, now=110, min_queries=2).keys() == {("h1", "evil.com")}
