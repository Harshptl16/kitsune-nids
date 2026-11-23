"""Attach a ground-truth label to each packet (owner: Rajbeer).

Reads a replay's meta CSV (from eval/replay.py) and the attack log written by
lab/attacks/attack_base.py, and marks a packet as attack (1) when its time falls
in an attack window AND it involves the attacker (by source or destination IP).
Everything else is benign (0).

    python -m eval.label data/run1.meta.csv lab/labels/attack_log.csv --out data/run1.labels.csv

Output: index, ts, label, run_id (the attack it belongs to, or empty).
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass
class Window:
    run_id: str
    start: float
    end: float
    attacker_ip: str
    targets: set[str]


def _epoch(iso: str) -> float:
    return datetime.fromisoformat(iso).timestamp()


def load_windows(attack_log: str | Path) -> list[Window]:
    wins = []
    with open(attack_log, newline="") as fh:
        for r in csv.DictReader(fh):
            targets = {t for t in r["target"].replace(",", " ").split()}
            wins.append(Window(r["run_id"], _epoch(r["start_utc"]), _epoch(r["end_utc"]),
                               r["attacker_ip"], targets))
    return wins


def label_row(ts: float, src_ip: str, dst_ip: str, windows: list[Window]) -> tuple[int, str]:
    for w in windows:
        if w.start <= ts <= w.end and (src_ip == w.attacker_ip or dst_ip == w.attacker_ip
                                       or src_ip in w.targets or dst_ip in w.targets):
            return 1, w.run_id
    return 0, ""


def label_meta(meta_csv: str | Path, attack_log: str | Path, out: str | Path) -> dict:
    windows = load_windows(attack_log)
    counts = {"benign": 0, "attack": 0}
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(meta_csv, newline="") as fin, open(out, "w", newline="") as fout:
        w = csv.writer(fout)
        w.writerow(("index", "ts", "label", "run_id"))
        for row in csv.DictReader(fin):
            label, run_id = label_row(float(row["ts"]), row["src_ip"], row["dst_ip"], windows)
            counts["attack" if label else "benign"] += 1
            w.writerow((row["index"], row["ts"], label, run_id))
    return counts


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("meta_csv", help="*.meta.csv from eval.replay")
    ap.add_argument("attack_log", help="lab/labels/attack_log.csv")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    counts = label_meta(args.meta_csv, args.attack_log, args.out)
    total = counts["benign"] + counts["attack"]
    print(f"labelled {total:,} packets: {counts['attack']:,} attack, {counts['benign']:,} benign")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
