"""Tests for labelling and metrics (owner: Rajbeer)."""

import csv
from datetime import datetime, timezone

import numpy as np
import pytest

from eval import metrics
from eval.label import label_meta, label_row, load_windows


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat()


def write_csv(path, cols, rows):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        w.writerows(rows)
    return path


# ---- labelling ----

def make_attack_log(tmp_path):
    return write_csv(tmp_path / "attack_log.csv",
                     ("run_id", "attack", "variant", "start_utc", "end_utc", "attacker_ip",
                      "attacker_mac", "target", "rate", "sent", "note"),
                     [("scan-1", "portscan", "syn", iso(100), iso(110), "10.10.0.66", "",
                       "10.10.0.10", 500, 300, "")])


def test_label_row_in_and_out_of_window(tmp_path):
    w = load_windows(make_attack_log(tmp_path))
    assert label_row(105, "10.10.0.66", "10.10.0.10", w) == (1, "scan-1")   # in window, attacker
    assert label_row(105, "10.10.0.20", "10.10.0.10", w)[0] == 1            # in window, involves target
    assert label_row(200, "10.10.0.66", "10.10.0.10", w) == (0, "")        # after window
    assert label_row(105, "10.10.0.20", "10.10.0.21", w) == (0, "")        # unrelated hosts


def test_label_meta_counts(tmp_path):
    log = make_attack_log(tmp_path)
    meta = write_csv(tmp_path / "run.meta.csv",
                     ("index", "ts", "src_mac", "src_ip", "dst_ip",
                      "src_port", "dst_port", "proto", "length"),
                     [(0, 50, "m", "10.10.0.20", "10.10.0.10", 1, 2, "tcp", 100),
                      (1, 105, "m", "10.10.0.66", "10.10.0.10", 1, 2, "tcp", 60),
                      (2, 106, "m", "10.10.0.66", "10.10.0.10", 1, 3, "tcp", 60)])
    counts = label_meta(meta, log, tmp_path / "out.csv")
    assert counts == {"benign": 1, "attack": 2}
    rows = list(csv.DictReader(open(tmp_path / "out.csv")))
    assert [r["label"] for r in rows] == ["0", "1", "1"]


# ---- metrics ----

def test_roc_auc_perfect_and_random():
    labels = [0, 0, 0, 1, 1, 1]
    assert metrics.roc_auc(labels, [0.1, 0.2, 0.3, 0.7, 0.8, 0.9]) == pytest.approx(1.0)
    assert metrics.roc_auc(labels, [0.9, 0.8, 0.7, 0.3, 0.2, 0.1]) == pytest.approx(0.0)


def test_roc_auc_matches_probability():
    rng = np.random.default_rng(0)
    neg = rng.normal(0, 1, 2000)
    pos = rng.normal(1, 1, 2000)
    labels = np.r_[np.zeros(2000), np.ones(2000)]
    scores = np.r_[neg, pos]
    brute = np.mean([p > n for p in pos[:200] for n in neg[:200]])
    assert metrics.roc_auc(labels, scores) == pytest.approx(brute, abs=0.03)


def test_roc_auc_ignores_nan():
    assert metrics.roc_auc([0, 1, 0, 1], [np.nan, np.nan, 0.1, 0.9]) == pytest.approx(1.0)


def test_tpr_fpr():
    labels = [0, 0, 1, 1]
    tpr, fpr = metrics.tpr_fpr(labels, [0.1, 0.6, 0.4, 0.9], 0.5)
    assert tpr == pytest.approx(0.5) and fpr == pytest.approx(0.5)


def test_equal_error_rate_separable():
    labels = [0] * 100 + [1] * 100
    scores = list(np.linspace(0, 0.4, 100)) + list(np.linspace(0.6, 1, 100))
    th, eer = metrics.equal_error_rate(labels, scores)
    assert 0.4 <= th <= 0.6 and eer < 0.05


def test_event_metrics():
    # one attack run from t=100 to 110; one alert at 102 (detected), one false alert at 50
    ts = [50, 100, 105, 110, 200]
    labels = [0, 1, 1, 1, 0]
    run_ids = ["", "scan-1", "scan-1", "scan-1", ""]
    res = metrics.event_metrics(ts, labels, run_ids, alert_starts=[50, 102], benign_seconds=3600)
    assert res["attack_runs"] == 1 and res["detected_runs"] == 1
    assert res["detection_rate"] == 1.0
    assert res["median_time_to_detect_s"] == pytest.approx(2.0)
    assert res["false_alerts"] == 1 and res["false_alerts_per_hour"] == pytest.approx(1.0)


def test_event_metrics_missed_run():
    res = metrics.event_metrics([100, 105], [1, 1], ["scan-1", "scan-1"],
                                alert_starts=[], benign_seconds=3600)
    assert res["detected_runs"] == 0 and res["detection_rate"] == 0.0
    assert np.isnan(res["median_time_to_detect_s"])
