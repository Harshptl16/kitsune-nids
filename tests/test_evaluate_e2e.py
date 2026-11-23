"""End-to-end: score a pcap, label it, run eval.evaluate (owner: Rajbeer)."""

import csv
from datetime import datetime, timezone

from eval.evaluate import run as evaluate_run
from eval.label import label_meta
from nids.cli import score_pcap
from nids.pipeline import Detector


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat()


def test_full_flow(port_scan_pcap, tmp_path):
    det = Detector.from_config(fm_grace=40, ad_grace=120)
    score_pcap(det, port_scan_pcap, tmp_path / "r.scores.csv", progress_every=0)

    # the scan packets in the fixture start after the benign block; find their window
    rows = list(csv.DictReader(open(tmp_path / "r.scores.csv")))
    scan = [float(r["ts"]) for r in rows if r["src_ip"] == "10.10.0.66"]
    with open(tmp_path / "attack_log.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(("run_id", "attack", "variant", "start_utc", "end_utc", "attacker_ip",
                    "attacker_mac", "target", "rate", "sent", "note"))
        w.writerow(("scan-1", "portscan", "syn", iso(min(scan)), iso(max(scan)),
                    "10.10.0.66", "", "10.10.0.10", 500, len(scan), ""))

    # meta.csv shares columns with scores.csv for labelling
    with open(tmp_path / "r.meta.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(("index", "ts", "src_mac", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "length"))
        for r in rows:
            w.writerow((r["index"], r["ts"], r["src_mac"], r["src_ip"], r["dst_ip"],
                        r["src_port"], r["dst_port"], r["proto"], r["length"]))

    counts = label_meta(tmp_path / "r.meta.csv", tmp_path / "attack_log.csv", tmp_path / "r.labels.csv")
    assert counts["attack"] == 300

    res = evaluate_run(tmp_path / "r.scores.csv", tmp_path / "r.labels.csv", None,
                       threshold=1.0, k=5, n=50, benign_seconds=60)
    assert res["roc_auc"] > 0.9
    assert res["detected_runs"] == 1
    assert res["tpr_at_threshold"] > 0.8
