"""Run the detector on live traffic or a replayed pcap, writing alerts to the store (owner: Harsh).

This is the piece the demo runs. It trains on the first packets, then scores each
later packet, raises debounced alerts and writes them (plus a score sample) to the
SQLite store the dashboard reads.

    # replay a recorded capture at full speed (good for testing the whole chain)
    python -m nids.live --pcap data/benign_then_scan.pcap --store data/live.sqlite

    # live on the sensor NIC (Linux, needs root)
    sudo .venv/bin/python -m nids.live --iface enp0s3 --store data/live.sqlite

    # train on one capture, save the model, then score a second one with it
    python -m nids.live --pcap data/benign_day1.pcap --save-model data/model.pkl --train-only
    python -m nids.live --pcap data/test.pcap --load-model data/model.pkl \
        --threshold 0.4 --store data/live.sqlite

With --load-model the model is already trained, so scoring and alerting start at
the first packet. Without it, the first fm_grace + ad_grace packets train the model.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from nids.capture import PcapSource
from nids.config import load_config
from nids.detect import Alerter, AlertStore, Threshold
from nids.model.kitnet import KitNET
from nids.pipeline import Detector


def make_source(args):
    if args.iface:
        from nids.capture.live_source import LiveSource
        return LiveSource(args.iface, bpf_filter=args.filter, limit=args.limit)
    return PcapSource(args.pcap, limit=args.limit)


def build_detector(args, cfg) -> Detector:
    det = Detector.from_config(args.config, fm_grace=args.fm_grace, ad_grace=args.ad_grace)
    if args.load_model:
        det.model = KitNET.load(args.load_model)   # pre-trained: scoring starts immediately
    return det


def run(args) -> dict:
    cfg = load_config(args.config)
    det = build_detector(args, cfg)
    threshold = None if args.threshold is None else Threshold(args.threshold, 0.999, 0)
    store = AlertStore(args.store) if args.store else None
    alerter = None
    sample_every = max(1, args.sample_every)

    counts = {"packets": 0, "scored": 0, "alerts": 0}
    source = make_source(args)
    t0 = time.perf_counter()
    try:
        for pkt in source:
            result = det.process(pkt)
            counts["packets"] += 1
            if not result.trained:
                continue
            counts["scored"] += 1

            # First scored packet and no threshold given: fit one from the benign
            # scores seen so far is not possible mid-stream, so require --threshold
            # for live alerting, or --train-only to just build a model.
            if threshold is None:
                if not args.train_only and counts["scored"] == 1:
                    print("no --threshold given: scoring only, not alerting "
                          "(fit one with nids.detect.Threshold on a benign run)", file=sys.stderr)
                continue
            if alerter is None:
                alerter = Alerter(threshold, k=args.k, n=args.n)

            if store and counts["scored"] % sample_every == 0:
                store.add_score(pkt.ts, result.score)
            alert = alerter.update(pkt, result.score)
            if alert:
                counts["alerts"] += 1
                print(alert.summary())
            if alerter.open_alert and store:
                store.save_alert(alerter.open_alert)
            if args.progress_every and counts["packets"] % args.progress_every == 0:
                rate = counts["packets"] / (time.perf_counter() - t0)
                print(f"  {counts['packets']:,} packets  {rate:,.0f} pkt/s  "
                      f"stage={det.model.stage}  alerts={counts['alerts']}", file=sys.stderr)
    except KeyboardInterrupt:
        print("stopped", file=sys.stderr)
    finally:
        if alerter and store:
            for a in alerter.alerts:
                store.save_alert(a)
        if store:
            store.close()

    if args.save_model and det.model.is_trained:
        det.model.save(args.save_model)
        print(f"saved model to {args.save_model}")
    return counts


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="nids.live", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="replay this capture")
    src.add_argument("--iface", help="sniff this interface live (Linux, root)")
    ap.add_argument("--filter", help="BPF filter for --iface")
    ap.add_argument("--store", type=Path, help="SQLite file for alerts and score samples")
    ap.add_argument("--threshold", type=float, help="alert threshold; without it, score only")
    ap.add_argument("--k", type=int, default=5, help="debounce: alert when k of last n exceed threshold")
    ap.add_argument("--n", type=int, default=50)
    ap.add_argument("--sample-every", type=int, default=10, help="store 1 score per N scored packets")
    ap.add_argument("--fm-grace", type=int)
    ap.add_argument("--ad-grace", type=int)
    ap.add_argument("--save-model", type=Path)
    ap.add_argument("--load-model", type=Path, help="use a pre-trained model (pickle you made)")
    ap.add_argument("--train-only", action="store_true", help="build/train a model, do not alert")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--progress-every", type=int, default=50_000)
    ap.add_argument("--config")
    args = ap.parse_args(argv)
    c = run(args)
    print(f"packets={c['packets']:,}  scored={c['scored']:,}  alerts={c['alerts']:,}")


if __name__ == "__main__":
    main()
