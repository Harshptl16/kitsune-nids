"""Tests for threshold, alerter and alert store (owner: Vrajkumar)."""

import numpy as np
import pytest

from nids.capture import Packet
from nids.detect import Alerter, AlertStore, Threshold


def pkt(t, src="10.10.0.20"):
    return Packet(t, "02:00:00:00:00:0a", "02:00:00:00:00:0b", src, "10.10.0.10", 1, 2, "tcp", 100)


def th(value=1.0):
    return Threshold(value=value, quantile=0.999, n_benign=1000)


def test_fit_threshold_quantile():
    rng = np.random.default_rng(0)
    benign = rng.lognormal(mean=-3, sigma=0.5, size=100_000)
    t = Threshold.fit(benign, 0.99)
    assert (benign > t.value).mean() == pytest.approx(0.01, abs=0.002)


def test_fit_ignores_nan_and_needs_data():
    with pytest.raises(ValueError):
        Threshold.fit([0.1] * 50)
    t = Threshold.fit([np.nan] * 10 + [0.1] * 200)
    assert t.n_benign == 200


def test_threshold_round_trip(tmp_path):
    t = Threshold.fit(np.linspace(0.01, 1, 1000), 0.999)
    t.save(tmp_path / "t.json")
    assert Threshold.load(tmp_path / "t.json") == t


def test_single_spike_does_not_alert():
    a = Alerter(th(), k=5, n=50)
    out = [a.update(pkt(i), 5.0 if i == 10 else 0.1) for i in range(100)]
    assert not any(out) and a.alerts == []


def test_burst_alerts_once_and_names_source():
    a = Alerter(th(), k=5, n=50)
    fired = []
    for i in range(300):
        attack = 100 <= i < 150
        r = a.update(pkt(i, "10.10.0.66" if attack else "10.10.0.20"), 9.0 if attack else 0.1)
        if r:
            fired.append(r)
    assert len(fired) == 1
    alert = fired[0]
    assert alert.start_ts == 104             # 5th over-threshold packet
    assert alert.top_sources[0] == ("10.10.0.66", 50)
    assert alert.end_ts is not None and alert.end_ts > 150


def test_two_bursts_two_alerts():
    a = Alerter(th(), k=3, n=10)
    for i in range(200):
        a.update(pkt(i), 5.0 if (20 <= i < 30 or 120 <= i < 130) else 0.1)
    assert [x.id for x in a.alerts] == [1, 2]


def test_bad_k_n():
    with pytest.raises(ValueError):
        Alerter(th(), k=10, n=5)


def test_store_round_trip(tmp_path):
    a = Alerter(th(), k=2, n=5)
    for i in range(20):
        a.update(pkt(i, "10.10.0.66"), 3.0 if i in (5, 6, 7) else 0.1)
    s = AlertStore(tmp_path / "alerts.sqlite")
    for x in a.alerts:
        s.save_alert(x)
    for i in range(10):
        s.add_score(float(i), 0.1 * i)
    s.flush()
    rows = s.recent_alerts()
    assert len(rows) == 1 and rows[0]["top_sources"][0] == ("10.10.0.66", 3)
    assert len(s.scores_since(5.0)) == 5
    s.close()
