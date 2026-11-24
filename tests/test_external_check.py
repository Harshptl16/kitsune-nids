"""Tests for the public-dataset check (owner: Krishkumar).

Uses a small synthetic stand-in for the dataset's CSV format (115 feature columns,
no header; a separate label column), so CI needs no download.
"""

import csv

import numpy as np

from eval.external_check import read_labels, read_rows, run


def write_dataset(tmp_path, n_benign=3000, n_attack=500, dim=20):
    """Benign rows follow two hidden factors; attack rows break the correlation."""
    rng = np.random.default_rng(0)
    feats = tmp_path / "feats.csv"
    labs = tmp_path / "labs.csv"
    with open(feats, "w", newline="") as ff, open(labs, "w", newline="") as fl:
        fw, lw = csv.writer(ff), csv.writer(fl)
        half = dim // 2
        for _ in range(n_benign):
            a, b = rng.uniform(0.2, 0.8), rng.uniform(0.2, 0.8)
            row = np.r_[a + rng.normal(0, 0.02, half), b + rng.normal(0, 0.02, dim - half)]
            fw.writerow([f"{v:.5f}" for v in row])
            lw.writerow([0])
        for _ in range(n_attack):
            row = np.r_[np.full(half, 0.85), np.full(dim - half, 0.15)] + rng.normal(0, 0.02, dim)
            fw.writerow([f"{v:.5f}" for v in row])
            lw.writerow([1])
    return feats, labs


def test_read_rows_and_labels(tmp_path):
    feats, labs = write_dataset(tmp_path, 10, 5, dim=20)
    rows = list(read_rows(feats))
    assert len(rows) == 15 and rows[0].shape == (20,)
    assert read_labels(labs).tolist() == [0] * 10 + [1] * 5


def test_labels_with_header_and_index_column(tmp_path):
    """The Kaggle copy of the labels has a header ("","x") and a row-number column."""
    labs = tmp_path / "labs.csv"
    labs.write_text('"","x"\n"1",0\n"2",0\n"3",1\n')
    assert read_labels(labs).tolist() == [0, 0, 1]
    assert read_labels(labs, limit=2).tolist() == [0, 0]


def test_limit(tmp_path):
    feats, labs = write_dataset(tmp_path, 10, 5)
    assert len(list(read_rows(feats, limit=8))) == 8
    assert len(read_labels(labs, limit=8)) == 8


def test_separates_attack_from_benign(tmp_path):
    feats, labs = write_dataset(tmp_path, 2500, 500, dim=20)
    res = run(str(feats), str(labs), fm_grace=200, ad_grace=2000)
    assert res["scored"] == 800          # 3000 - 2200 training
    assert res["attack_scored"] == 500
    assert res["roc_auc"] > 0.95
