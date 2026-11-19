"""Replay a pcap (or a live interface) through the feature extractor (owner: Rajbeer).

Writes one row of 115 features per packet, plus a small metadata CSV so later
phases can join features with ground-truth labels.

    python -m eval.replay data/benign_day1.pcap --out data/benign_day1
        -> data/benign_day1.features.npy   float32, shape (packets, 115)
           data/benign_day1.meta.csv       ts, src_mac, src_ip, dst_ip, sport, dport, proto, length

    sudo -E python -m eval.replay --live enp0s8 --limit 20000 --out data/live_test
"""

from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path

import numpy as np

from nids.capture import PcapSource
from nids.config import extractor_kwargs, load_config
from nids.features import FeatureExtractor

META_COLS = ("ts", "src_mac", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "length")


def make_source(args):
    if args.live:
        from nids.capture.live_source import LiveSource
        return LiveSource(args.live, bpf_filter=args.filter, limit=args.limit)
    return PcapSource(args.pcap, limit=args.limit)


def replay(source, extractor: FeatureExtractor, out: Path | None, progress_every: int = 50_000):
    rows, n = [], 0
    meta_fh = writer = None
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        meta_fh = open(out.with_suffix(".meta.csv"), "w", newline="")
        writer = csv.writer(meta_fh)
        writer.writerow(META_COLS)
    t0 = time.perf_counter()
    try:
        for pkt in source:
            rows.append(extractor.process(pkt).astype(np.float32))
            if writer is not None:
                writer.writerow([f"{pkt.ts:.6f}", pkt.src_mac, pkt.src_ip, pkt.dst_ip,
                                 pkt.src_port, pkt.dst_port, pkt.proto, pkt.length])
            n += 1
            if progress_every and n % progress_every == 0:
                rate = n / (time.perf_counter() - t0)
                print(f"  {n:,} packets  {rate:,.0f} pkt/s  streams={len(extractor.table):,}",
                      file=sys.stderr)
    except KeyboardInterrupt:
        print("stopped by user", file=sys.stderr)
    finally:
        if meta_fh is not None:
            meta_fh.close()
    elapsed = time.perf_counter() - t0
    feats = np.vstack(rows) if rows else np.zeros((0, extractor.n_features), np.float32)
    if out is not None:
        np.save(out.with_suffix(".features.npy"), feats)
    return feats, elapsed


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", nargs="?", help="input .pcap/.pcapng")
    ap.add_argument("--live", metavar="IFACE", help="sniff this interface instead of reading a file")
    ap.add_argument("--filter", help="BPF filter for --live, e.g. 'not port 22'")
    ap.add_argument("--out", type=Path, help="output prefix (no extension)")
    ap.add_argument("--limit", type=int, help="stop after N packets")
    ap.add_argument("--config", help="YAML overriding configs/default.yaml")
    args = ap.parse_args(argv)
    if not args.pcap and not args.live:
        ap.error("give a pcap path or --live IFACE")

    fe = FeatureExtractor(**extractor_kwargs(load_config(args.config)))
    src = make_source(args)
    feats, elapsed = replay(src, fe, args.out)
    n = len(feats)
    print(f"packets={n:,}  seconds={elapsed:.2f}  pkt/s={n / max(elapsed, 1e-9):,.0f}  "
          f"skipped={getattr(src, 'skipped', 0)}  dropped={getattr(src, 'dropped', 0)}")
    if args.out:
        print(f"wrote {args.out.with_suffix('.features.npy')} and {args.out.with_suffix('.meta.csv')}")


if __name__ == "__main__":
    main()
