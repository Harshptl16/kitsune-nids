"""Score one capture with all three detectors and emit per-detector results (owner: Harsh).

Runs KitNET, the Random Forest and the rule detector on the same labelled capture
and writes one eval.evaluate-style JSON per detector, so eval.report builds the
comparison table from a single command.

    python -m eval.compare --pcap data/test.pcap --labels data/test.labels.csv \
        --features data/test.features.npy --train-features data/benign.features.npy \
        --train-labels data/benign.labels.csv --threshold 0.4 --out-dir results/

- KitNET trains on the start of --pcap (benign first), scores the rest.
- Random Forest trains on --train-features/--train-labels (labelled), scores --features.
- Rules need no training.
All three are scored only on the packets KitNET scored (after its grace period), so
the comparison is on the same rows.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from baselines import score_packets
from baselines.dataset import holdout_split, load_xy
from baselines.random_forest import RandomForestBaseline
from baselines.rules import RuleDetector
from eval import metrics
from nids.capture import PcapSource
from nids.pipeline import Detector


def _event_block(ts, labels, run_ids, scores, threshold, benign_seconds):
    tpr, fpr = metrics.tpr_fpr(labels, scores, threshold)
    out = {
        "roc_auc": round(metrics.roc_auc(labels, scores), 4),
        "tpr_at_threshold": round(tpr, 4),
        "fpr_at_threshold": round(fpr, 4),
        "threshold": threshold,
        "scored_packets": int(len(scores)),
        "attack_packets": int(np.sum(labels)),
    }
    # events from simple above-threshold runs (no debounce here; report-level view)
    starts = [ts[i] for i in range(len(scores)) if scores[i] > threshold]
    out.update(metrics.event_metrics(ts, labels, run_ids, starts[:1] or [], benign_seconds))
    return out


def run(pcap, labels_csv, features_npy, train_features, train_labels, threshold,
        hold_out, benign_seconds, fm_grace=None, ad_grace=None) -> dict:
    import csv
    # labels aligned to the pcap, by packet index
    with open(labels_csv, newline="") as fh:
        lab_rows = list(csv.DictReader(fh))
    labels_all = np.array([int(r["label"]) for r in lab_rows])
    runs_all = np.array([r.get("run_id", "") for r in lab_rows], dtype=object)

    # --- KitNET: train on the start of the pcap, score the rest ---
    det = Detector.from_config(fm_grace=fm_grace, ad_grace=ad_grace)
    packets, kit_scores, scored_mask, ts = [], [], [], []
    for pkt in PcapSource(pcap):
        packets.append(pkt)
        r = det.process(pkt)
        scored_mask.append(r.trained)
        kit_scores.append(r.score if r.trained else np.nan)
        ts.append(pkt.ts)
    scored_mask = np.array(scored_mask)
    ts = np.array(ts)
    labels = labels_all[: len(packets)][scored_mask]
    run_ids = runs_all[: len(packets)][scored_mask]
    ts_s = ts[scored_mask]

    results = {}
    results["kitsune"] = _event_block(ts_s, labels, run_ids,
                                      np.array(kit_scores)[scored_mask], threshold, benign_seconds)

    # --- Rules: score the same packets ---
    rule_scores = score_packets(RuleDetector(), packets)[scored_mask]
    results["rules"] = _event_block(ts_s, labels, run_ids, rule_scores, 0.5, benign_seconds)

    # --- Random Forest: train on labelled training data, score the scored packets ---
    if train_features and train_labels:
        ds = load_xy(train_features, train_labels)
        tr, _ = holdout_split(ds, hold_out_run_prefix=hold_out)
        rf = RandomForestBaseline().fit(ds.X[tr], ds.y[tr])
        X_test = np.load(features_npy)[: len(packets)][scored_mask]
        results["rf"] = _event_block(ts_s, labels, run_ids, rf.score(X_test), 0.5, benign_seconds)

    for name, block in results.items():
        block["detector"] = name
    return results


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--labels", required=True, help="labels.csv aligned to --pcap")
    ap.add_argument("--features", help="features.npy aligned to --pcap (for the Random Forest)")
    ap.add_argument("--train-features")
    ap.add_argument("--train-labels")
    ap.add_argument("--hold-out", help="attack run prefix to keep out of RF training, e.g. arpspoof")
    ap.add_argument("--threshold", type=float, required=True, help="KitNET alert threshold")
    ap.add_argument("--benign-seconds", type=float, default=0)
    ap.add_argument("--fm-grace", type=int)
    ap.add_argument("--ad-grace", type=int)
    ap.add_argument("--out-dir", type=Path)
    args = ap.parse_args(argv)
    results = run(args.pcap, args.labels, args.features, args.train_features, args.train_labels,
                  args.threshold, args.hold_out, args.benign_seconds, args.fm_grace, args.ad_grace)
    print(json.dumps(results, indent=2))
    if args.out_dir:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        attack = args.hold_out or "all"
        for name, block in results.items():
            (args.out_dir / f"{name}_{attack}.json").write_text(json.dumps(block, indent=2))
        print(f"wrote {len(results)} result files to {args.out_dir}")


if __name__ == "__main__":
    main()
