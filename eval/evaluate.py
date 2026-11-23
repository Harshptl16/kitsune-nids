"""One command that scores a run and prints the evaluation table (owner: Rajbeer).

Joins three files by packet index: scores (from nids.cli score --out), labels
(from eval.label), and the meta CSV (for timestamps), then prints packet-level
and event-level metrics for the KitNET detector.

    python -m eval.evaluate --scores data/run1.scores.csv --labels data/run1.labels.csv \
        --meta data/run1.meta.csv --threshold 0.2 --benign-seconds 7200

Alerts are recomputed from the scores with the given threshold and debounce, so
this does not need a separate alert file.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import numpy as np

from eval import metrics
from nids.capture import Packet
from nids.detect import Alerter, Threshold


def _read(path, cols):
    with open(path, newline="") as fh:
        rows = list(csv.DictReader(fh))
    return {c: [r[c] for r in rows] for c in cols}


def run(scores_csv, labels_csv, meta_csv, threshold, k, n, benign_seconds) -> dict:
    sc = _read(scores_csv, ("index", "ts", "score", "trained", "src_ip", "dst_ip", "src_mac",
                            "src_port", "dst_port", "proto", "length"))
    lb = _read(labels_csv, ("index", "label", "run_id"))
    by_index = dict(zip(lb["index"], zip(lb["label"], lb["run_id"], strict=True), strict=True))

    ts, scores, labels, run_ids = [], [], [], []
    alerter = Alerter(Threshold(value=threshold, quantile=0.999, n_benign=0), k=k, n=n)
    for i in range(len(sc["index"])):
        if sc["trained"][i] != "1":            # skip packets used for training
            continue
        idx = sc["index"][i]
        label, run_id = by_index.get(idx, ("0", ""))
        t, s = float(sc["ts"][i]), float(sc["score"][i])
        ts.append(t)
        scores.append(s)
        labels.append(int(label))
        run_ids.append(run_id)
        pkt = Packet(t, sc["src_mac"][i], "", sc["src_ip"][i], sc["dst_ip"][i],
                     int(sc["src_port"][i]), int(sc["dst_port"][i]), sc["proto"][i], int(sc["length"][i]))
        alerter.update(pkt, s)

    tpr, fpr = metrics.tpr_fpr(labels, scores, threshold)
    eer_th, eer = metrics.equal_error_rate(labels, scores)
    out = {
        "scored_packets": len(scores),
        "attack_packets": int(np.sum(labels)),
        "roc_auc": round(metrics.roc_auc(labels, scores), 4),
        "eer": round(eer, 4),
        "tpr_at_threshold": round(tpr, 4),
        "fpr_at_threshold": round(fpr, 4),
        "threshold": threshold,
    }
    out.update(metrics.event_metrics(ts, labels, run_ids,
                                     [a.start_ts for a in alerter.alerts], benign_seconds))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scores", required=True)
    ap.add_argument("--labels", required=True)
    ap.add_argument("--meta", help="unused; kept so the three files can be passed together")
    ap.add_argument("--threshold", type=float, required=True)
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--n", type=int, default=50)
    ap.add_argument("--benign-seconds", type=float, default=0)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)
    res = run(args.scores, args.labels, args.meta, args.threshold, args.k, args.n, args.benign_seconds)
    print(json.dumps(res, indent=2))
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(res, indent=2))
        print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
