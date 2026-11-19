"""Measure throughput of each pipeline stage separately (owner: Rajbeer).

    python -m eval.benchmark data/benign_day1.pcap --limit 200000
    python -m eval.benchmark --synthetic 50000        # no pcap needed (used in CI)

Reports packets/s for parsing alone and for parsing + feature extraction, and
the per-packet extraction latency (median and p99). Results are appended to
results/benchmarks.jsonl with the machine details, so numbers from different
laptops and optimisation steps can be compared later.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from nids.capture import Packet, PcapSource
from nids.features import FeatureExtractor


def synthetic_packets(n: int, seed: int = 0) -> list[Packet]:
    """A mix of 20 clients talking to 3 servers, with realistic sizes and gaps."""
    rng = np.random.default_rng(seed)
    t, out = 0.0, []
    for _ in range(n):
        t += float(rng.exponential(0.001))
        c, s = int(rng.integers(20, 40)), int(rng.integers(10, 13))
        up = rng.random() < 0.5
        src, dst = (f"10.10.0.{c}", f"10.10.0.{s}") if up else (f"10.10.0.{s}", f"10.10.0.{c}")
        sp, dp = (40000 + c, 80) if up else (80, 40000 + c)
        out.append(Packet(t, f"02:00:00:00:00:{c:02x}", "02:00:00:00:00:01", src, dst, sp, dp,
                          "tcp", int(rng.integers(60, 1514))))
    return out


def run(packets_factory, label: str) -> dict:
    # Stage 1: parse only
    t0 = time.perf_counter()
    pkts = list(packets_factory())
    parse_s = time.perf_counter() - t0

    # Stage 2: feature extraction, timed per packet
    fe = FeatureExtractor()
    lat = np.empty(len(pkts))
    t0 = time.perf_counter()
    for i, p in enumerate(pkts):
        s = time.perf_counter()
        fe.process(p)
        lat[i] = time.perf_counter() - s
    extract_s = time.perf_counter() - t0

    n = len(pkts)
    return {
        "when": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "input": label,
        "packets": n,
        "parse_pkt_per_s": round(n / max(parse_s, 1e-9)),
        "extract_pkt_per_s": round(n / max(extract_s, 1e-9)),
        "extract_latency_us_median": round(float(np.median(lat)) * 1e6, 1) if n else None,
        "extract_latency_us_p99": round(float(np.percentile(lat, 99)) * 1e6, 1) if n else None,
        "streams_at_end": len(fe.table),
        "python": platform.python_version(),
        "machine": platform.processor() or platform.machine(),
        "cpus": os.cpu_count(),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", nargs="?")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--synthetic", type=int, metavar="N", help="benchmark N generated packets")
    ap.add_argument("--results", type=Path, default=Path("results/benchmarks.jsonl"))
    args = ap.parse_args(argv)

    if args.synthetic:
        res = run(lambda: synthetic_packets(args.synthetic), f"synthetic:{args.synthetic}")
    elif args.pcap:
        res = run(lambda: PcapSource(args.pcap, limit=args.limit), args.pcap)
    else:
        ap.error("give a pcap path or --synthetic N")

    print(json.dumps(res, indent=2))
    args.results.parent.mkdir(parents=True, exist_ok=True)
    with open(args.results, "a") as fh:
        fh.write(json.dumps(res) + "\n")


if __name__ == "__main__":
    main()
