"""Collect evaluation results into the comparison table for the report (owner: Rajbeer).

Each run of eval.evaluate writes one JSON result. This gathers several of them,
one per (detector, attack), and renders the results table from the project plan as
Markdown and CSV, so the numbers in the report come straight from the tool and are
reproducible.

    # after running eval.evaluate for each detector/attack with --out results/<detector>_<attack>.json
    python -m eval.report results/*.json --out results/table

Each input JSON must also carry "detector" and "attack" keys (add them with
--detector/--attack when you run evaluate, or they default from the file name).
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

COLUMNS = [
    ("detector", "Detector"),
    ("attack", "Attack"),
    ("tpr_at_threshold", "TPR"),
    ("fpr_at_threshold", "FPR"),
    ("roc_auc", "AUC"),
    ("detected_runs", "Detected"),
    ("median_time_to_detect_s", "Median TTD (s)"),
    ("false_alerts_per_hour", "False/h"),
]


def load_results(paths, default_detector=None, default_attack=None) -> list[dict]:
    out = []
    for p in paths:
        p = Path(p)
        data = json.loads(p.read_text())
        stem = p.stem
        parts = stem.split("_", 1)
        data.setdefault("detector", default_detector or (parts[0] if parts else stem))
        data.setdefault("attack", default_attack or (parts[1] if len(parts) > 1 else "?"))
        out.append(data)
    return out


def _fmt(v) -> str:
    if v is None:
        return "-"
    if isinstance(v, float):
        return "-" if v != v else f"{v:.3g}"      # NaN -> "-"
    return str(v)


def to_markdown(results: list[dict]) -> str:
    results = sorted(results, key=lambda r: (r.get("attack", ""), r.get("detector", "")))
    head = "| " + " | ".join(label for _, label in COLUMNS) + " |"
    sep = "| " + " | ".join("---" for _ in COLUMNS) + " |"
    rows = ["| " + " | ".join(_fmt(r.get(key)) for key, _ in COLUMNS) + " |" for r in results]
    return "\n".join([head, sep, *rows])


def to_csv(results: list[dict], path: Path) -> None:
    results = sorted(results, key=lambda r: (r.get("attack", ""), r.get("detector", "")))
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow([label for _, label in COLUMNS])
        for r in results:
            w.writerow([_fmt(r.get(key)) for key, _ in COLUMNS])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("results", nargs="+", help="eval.evaluate JSON files")
    ap.add_argument("--out", type=Path, help="write <out>.md and <out>.csv")
    args = ap.parse_args(argv)
    results = load_results(args.results)
    md = to_markdown(results)
    print(md)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.with_suffix(".md").write_text(md + "\n")
        to_csv(results, args.out.with_suffix(".csv"))
        print(f"\nwrote {args.out.with_suffix('.md')} and {args.out.with_suffix('.csv')}")


if __name__ == "__main__":
    main()
