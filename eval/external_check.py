"""Validate the model against the public Kitsune dataset (owner: Krishkumar).

The published dataset gives, per attack, a CSV of 115 pre-extracted features (one
row per packet, no header) and a label CSV (0 benign, 1 attack). This runs our own
KitNET on those features and reports how well the anomaly score separates attack
from benign — our Gate 2 check that the model behaves like the paper before we
trust our own lab results.

    python -m eval.external_check --features Mirai_dataset.csv --labels Mirai_labels.csv

Download from the dataset's page (see lab/README.md). The feature CSV can be large;
--limit caps the rows read. Training uses the benign rows at the start, as the
dataset is laid out (benign first, then the attack).
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import numpy as np

from eval.metrics import roc_auc
from nids.model.kitnet import KitNET


def read_rows(path: str | Path, limit: int | None = None):
    with open(path, newline="") as fh:
        for i, row in enumerate(csv.reader(fh)):
            if limit is not None and i >= limit:
                return
            yield np.array(row, dtype=float)


def read_labels(path: str | Path, limit: int | None = None) -> np.ndarray:
    vals = []
    with open(path, newline="") as fh:
        for row in csv.reader(fh):
            if limit is not None and len(vals) >= limit:
                break
            try:
                vals.append(int(float(row[-1])))  # label is the last (often only) column
            except ValueError:
                continue                          # header row, e.g. "","x" in the Kaggle copy
    return np.array(vals)


def run(features: str, labels_path: str, fm_grace: int, ad_grace: int, limit=None) -> dict:
    labels = read_labels(labels_path, limit)
    scores = np.full(len(labels), np.nan)
    model = None
    for i, x in enumerate(read_rows(features, limit)):
        if model is None:
            model = KitNET(len(x), fm_grace=fm_grace, ad_grace=ad_grace, seed=0)
        trained = model.is_trained          # check before process, like Detector does
        s = model.process(x)
        if trained:
            scores[i] = s
    scored = np.isfinite(scores)
    y = labels[scored]
    auc = roc_auc(y, scores[scored]) if scored.any() else float("nan")
    return {
        "rows": int(len(labels)),
        "trained_on": int((~scored).sum()),
        "scored": int(scored.sum()),
        "attack_scored": int(y.sum()),
        "benign_scored": int((y == 0).sum()),
        "roc_auc": round(auc, 4),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--features", required=True, help="115-column feature CSV (no header)")
    ap.add_argument("--labels", required=True, help="label CSV (0/1)")
    ap.add_argument("--fm-grace", type=int, default=5000)
    ap.add_argument("--ad-grace", type=int, default=50000)
    ap.add_argument("--limit", type=int, help="read only the first N rows")
    args = ap.parse_args(argv)
    res = run(args.features, args.labels, args.fm_grace, args.ad_grace, args.limit)
    import json
    print(json.dumps(res, indent=2))
    if res["roc_auc"] == res["roc_auc"] and res["roc_auc"] < 0.9:
        print("WARNING: AUC below 0.9 — check grace periods and that benign rows come first")


if __name__ == "__main__":
    main()
