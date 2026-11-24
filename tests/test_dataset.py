"""Tests for the baseline training-data builder (owner: Krishkumar)."""

import csv

import numpy as np
import pytest

from baselines.dataset import class_counts, holdout_split, load_xy


def make_files(tmp_path, n_benign=200, runs=(("scan", 100), ("arpspoof", 100))):
    rows = []
    feats = []
    rng = np.random.default_rng(0)
    for _ in range(n_benign):
        feats.append(rng.normal(0, 1, 115))
        rows.append((0, ""))
    for name, count in runs:
        for _ in range(count):
            feats.append(rng.normal(3, 1, 115))
            rows.append((1, f"{name}-1"))
    np.save(tmp_path / "f.npy", np.array(feats))
    with open(tmp_path / "l.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(("index", "ts", "label", "run_id"))
        for i, (lab, run) in enumerate(rows):
            w.writerow((i, i * 0.1, lab, run))
    return tmp_path / "f.npy", tmp_path / "l.csv"


def test_load_xy(tmp_path):
    f, lf = make_files(tmp_path)
    ds = load_xy(str(f), str(lf))
    assert ds.X.shape == (400, 115)
    assert class_counts(ds.y) == {"benign": 200, "attack": 200}
    assert set(ds.run_ids) == {"", "scan-1", "arpspoof-1"}


def test_length_mismatch_raises(tmp_path):
    f, lf = make_files(tmp_path)
    np.save(tmp_path / "f.npy", np.zeros((399, 115)))
    with pytest.raises(ValueError):
        load_xy(str(tmp_path / "f.npy"), str(lf))


def test_holdout_keeps_attack_out_of_training(tmp_path):
    f, lf = make_files(tmp_path)
    ds = load_xy(str(f), str(lf))
    train, test = holdout_split(ds, hold_out_run_prefix="arpspoof")
    # no arpspoof row is in training
    assert not any(str(r).startswith("arpspoof") and train[i] for i, r in enumerate(ds.run_ids))
    # every arpspoof row is in test
    assert all(test[i] for i, r in enumerate(ds.run_ids) if str(r).startswith("arpspoof"))
    # scan (seen) attack rows are all in training
    assert all(train[i] for i, r in enumerate(ds.run_ids) if str(r).startswith("scan"))
    assert not (train & test).any()


def test_plain_split_is_stratified(tmp_path):
    f, lf = make_files(tmp_path)
    ds = load_xy(str(f), str(lf))
    train, test = holdout_split(ds, test_fraction=0.25)
    assert abs(test.sum() / len(ds.y) - 0.25) < 0.02
    # both classes present in both sides
    assert class_counts(ds.y[train])["attack"] > 0 and class_counts(ds.y[test])["attack"] > 0


def test_split_is_disjoint_and_covers_all(tmp_path):
    f, lf = make_files(tmp_path)
    ds = load_xy(str(f), str(lf))
    train, test = holdout_split(ds, hold_out_run_prefix="scan")
    assert not (train & test).any()
    # every row is assigned somewhere (benign split + held attack + seen attack)
    assert (train | test).all()
