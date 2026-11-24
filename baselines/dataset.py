"""Build training/test matrices for the supervised baselines (owner: Krishkumar).

The anomaly model (KitNET) trains on benign traffic only. The supervised
baselines (Random Forest) instead need labelled rows: the 115 features from a
replay (eval.replay -> *.features.npy) joined with per-packet labels
(eval.label -> *.labels.csv).

A key experiment is the *unseen attack*: train the Random Forest on some attacks
but hold one out entirely (e.g. ARP spoofing), then test on it. This shows the
main argument for anomaly detection — the baseline only catches attacks it was
trained on.

    X, y, meta = load_xy("data/test.features.npy", "data/test.labels.csv")
    tr, te = holdout_split(y, meta, hold_out_run_prefix="arpspoof")
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass
class Dataset:
    X: np.ndarray                 # (n, 115) features
    y: np.ndarray                 # (n,) 0/1 labels
    run_ids: np.ndarray           # (n,) attack run id per row ('' for benign)


def load_xy(features_npy: str, labels_csv: str) -> Dataset:
    import csv
    X = np.load(features_npy)
    labels, runs = [], []
    with open(labels_csv, newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            labels.append(int(row["label"]))
            runs.append(row.get("run_id", ""))
    y = np.array(labels)
    run_ids = np.array(runs, dtype=object)
    if len(y) != len(X):
        raise ValueError(f"features ({len(X)}) and labels ({len(y)}) have different lengths")
    return Dataset(X=X, y=y, run_ids=run_ids)


def holdout_split(ds: Dataset, hold_out_run_prefix: str | None = None,
                  test_fraction: float = 0.3, seed: int = 0) -> tuple[np.ndarray, np.ndarray]:
    """Return boolean (train_mask, test_mask) over the rows.

    If hold_out_run_prefix is given, every row from a matching attack run goes to
    test only (never trained on), and benign rows are split by fraction. Otherwise
    a plain stratified-by-label random split.
    """
    n = len(ds.y)
    rng = np.random.default_rng(seed)
    train = np.zeros(n, dtype=bool)
    test = np.zeros(n, dtype=bool)

    if hold_out_run_prefix:
        held = np.array([str(r).startswith(hold_out_run_prefix) for r in ds.run_ids])
        test |= held
        # benign rows: split by fraction; other (seen) attack rows: all train
        benign = (ds.y == 0)
        seen_attack = (ds.y == 1) & ~held
        b_idx = np.where(benign)[0]
        rng.shuffle(b_idx)
        cut = int(len(b_idx) * test_fraction)
        test[b_idx[:cut]] = True
        train[b_idx[cut:]] = True
        train[seen_attack] = True
    else:
        for label in (0, 1):
            idx = np.where(ds.y == label)[0]
            rng.shuffle(idx)
            cut = int(len(idx) * test_fraction)
            test[idx[:cut]] = True
            train[idx[cut:]] = True
    return train, test


def class_counts(y: np.ndarray) -> dict:
    return {"benign": int((y == 0).sum()), "attack": int((y == 1).sum())}
