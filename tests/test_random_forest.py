"""Tests for the Random Forest baseline (owner: Rajbeer)."""

import numpy as np
import pytest

from baselines.dataset import Dataset, holdout_split
from baselines.random_forest import RandomForestBaseline
from eval.metrics import roc_auc


def synth(rng, n_benign=600, per_attack=300, dim=115):
    """Benign near 0; 'scan' shifts the first half of features, 'spoof' the second half."""
    X, y, runs = [], [], []
    for _ in range(n_benign):
        X.append(rng.normal(0, 1, dim))
        y.append(0)
        runs.append("")
    for _ in range(per_attack):
        v = rng.normal(0, 1, dim)
        v[: dim // 2] += 4
        X.append(v)
        y.append(1)
        runs.append("scan-1")
    for _ in range(per_attack):
        v = rng.normal(0, 1, dim)
        v[dim // 2:] += 4
        X.append(v)
        y.append(1)
        runs.append("arpspoof-1")
    return Dataset(np.array(X), np.array(y), np.array(runs, dtype=object))


def test_fit_requires_both_classes():
    rf = RandomForestBaseline(n_estimators=10)
    with pytest.raises(ValueError):
        rf.fit(np.zeros((10, 5)), np.zeros(10))


def test_scores_separate_seen_attack():
    rng = np.random.default_rng(0)
    ds = synth(rng)
    train, test = holdout_split(ds, test_fraction=0.3, seed=1)
    rf = RandomForestBaseline(n_estimators=50, seed=0).fit(ds.X[train], ds.y[train])
    auc = roc_auc(ds.y[test], rf.score(ds.X[test]))
    assert auc > 0.95


def test_unseen_attack_is_harder_than_seen():
    """The core experiment: RF trained without arpspoof detects it worse than the seen scan."""
    rng = np.random.default_rng(2)
    ds = synth(rng)
    train, _ = holdout_split(ds, hold_out_run_prefix="arpspoof", seed=1)
    rf = RandomForestBaseline(n_estimators=80, seed=0).fit(ds.X[train], ds.y[train])

    benign = ds.X[ds.y == 0]
    scan = ds.X[np.array([r == "scan-1" for r in ds.run_ids])]
    spoof = ds.X[np.array([r == "arpspoof-1" for r in ds.run_ids])]
    b = rf.score(benign)
    # seen attack scores clearly above benign; unseen attack is caught far less
    assert rf.score(scan).mean() > b.mean() + 0.3
    assert rf.score(spoof).mean() < rf.score(scan).mean()


def test_feature_importances():
    rng = np.random.default_rng(3)
    ds = synth(rng, dim=115)
    train, _ = holdout_split(ds, seed=1)
    rf = RandomForestBaseline(n_estimators=30, seed=0).fit(ds.X[train], ds.y[train])
    imp = rf.feature_importances(top=5)
    assert len(imp) == 5 and imp[0][1] >= imp[-1][1]


def test_save_load(tmp_path):
    rng = np.random.default_rng(4)
    ds = synth(rng)
    train, test = holdout_split(ds, seed=1)
    rf = RandomForestBaseline(n_estimators=20, seed=0).fit(ds.X[train], ds.y[train])
    rf.save(tmp_path / "rf.pkl")
    loaded = RandomForestBaseline.load(tmp_path / "rf.pkl")
    assert np.allclose(loaded.score(ds.X[test]), rf.score(ds.X[test]))
