"""Command line: score every packet in a pcap (owner: Harsh).

The first fm_grace + ad_grace packets train the model, so the capture must start
with benign traffic. Every later packet gets an anomaly score.

    python -m nids.cli score data/benign_then_scan.pcap --out data/run1.scores.csv
    python -m nids.cli score data/big.pcap --fm-grace 5000 --ad-grace 50000 --save-model data/model.pkl

Output CSV columns: index, ts, score, trained, src_mac, src_ip, dst_ip, src_port,
dst_port, proto, length. Rows with trained=0 were used for training (score 0).
"""

from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path

import numpy as np

from nids.capture import PcapSource
from nids.pipeline import Detector

COLS = ("index", "ts", "score", "trained", "src_mac", "src_ip", "dst_ip",
        "src_port", "dst_port", "proto", "length")


def score_pcap(det: Detector, pcap: str, out: Path | None, limit: int | None = None,
               progress_every: int = 50_000) -> np.ndarray:
    scores = []
    fh = open(out, "w", newline="") if out else None  # noqa: SIM115 (closed in finally)
    try:
        w = csv.writer(fh) if fh else None
        if w:
            w.writerow(COLS)
        t0 = time.perf_counter()
        for i, pkt in enumerate(PcapSource(pcap, limit=limit)):
            r = det.process(pkt)
            scores.append(r.score if r.trained else np.nan)
            if w:
                w.writerow([i, f"{pkt.ts:.6f}", f"{r.score:.6g}", int(r.trained), pkt.src_mac, pkt.src_ip,
                            pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.proto, pkt.length])
            if progress_every and (i + 1) % progress_every == 0:
                rate = (i + 1) / (time.perf_counter() - t0)
                print(f"  {i + 1:,} packets  {rate:,.0f} pkt/s  stage={det.model.stage}", file=sys.stderr)
    finally:
        if fh:
            fh.close()
    return np.array(scores, dtype=float)


def cmd_score(args) -> None:
    det = Detector.from_config(args.config, fm_grace=args.fm_grace, ad_grace=args.ad_grace)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    scores = score_pcap(det, args.pcap, args.out, args.limit)
    secs = time.perf_counter() - t0
    scored = scores[~np.isnan(scores)]
    print(f"packets={len(scores):,}  trained_on={len(scores) - len(scored):,}  scored={len(scored):,}  "
          f"seconds={secs:.1f}  pkt/s={len(scores) / max(secs, 1e-9):,.0f}")
    if len(scored):
        print(f"score median={np.median(scored):.4g}  "
              f"p99={np.percentile(scored, 99):.4g}  max={scored.max():.4g}")
    else:
        print("no packets scored: the capture is shorter than fm_grace + ad_grace")
    if args.save_model:
        det.model.save(args.save_model)
        print(f"saved model to {args.save_model}")
    if args.out:
        print(f"wrote {args.out}")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="nids", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("score", help="train on the start of a pcap, score the rest")
    s.add_argument("pcap")
    s.add_argument("--out", type=Path, help="CSV of per-packet scores")
    s.add_argument("--limit", type=int, help="stop after N packets")
    s.add_argument("--fm-grace", type=int, help="packets for the feature map (default from config)")
    s.add_argument("--ad-grace", type=int, help="packets for training (default from config)")
    s.add_argument("--save-model", type=Path, help="pickle the trained model here")
    s.add_argument("--config", help="YAML overriding configs/default.yaml")
    s.set_defaults(func=cmd_score)
    args = ap.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
