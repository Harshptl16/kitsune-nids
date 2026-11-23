"""End-to-end tests: pcap -> features -> KitNET -> scores (owner: Harsh)."""

import csv

import numpy as np

from nids.capture import PcapSource
from nids.cli import main, score_pcap
from nids.pipeline import Detector


def test_detector_trains_then_scores(port_scan_pcap):
    det = Detector.from_config(fm_grace=40, ad_grace=120)
    results = [det.process(p) for p in PcapSource(port_scan_pcap)]
    assert not any(r.trained for r in results[:160])
    assert all(r.trained for r in results[161:])
    assert all(r.score == 0.0 for r in results[:160])


def test_port_scan_scores_above_benign(port_scan_pcap):
    det = Detector.from_config(fm_grace=40, ad_grace=120)
    results = [det.process(p) for p in PcapSource(port_scan_pcap)]
    benign = [r.score for r in results if r.trained and r.packet.src_ip != "10.10.0.66"]
    scan = [r.score for r in results if r.trained and r.packet.src_ip == "10.10.0.66"]
    assert len(benign) > 20 and len(scan) == 300
    assert np.median(scan) > 2 * np.max(benign)


def test_score_pcap_writes_csv(port_scan_pcap, tmp_path):
    out = tmp_path / "s.csv"
    det = Detector.from_config(fm_grace=40, ad_grace=120)
    scores = score_pcap(det, port_scan_pcap, out, progress_every=0)
    rows = list(csv.DictReader(open(out)))
    n = sum(1 for _ in PcapSource(port_scan_pcap))
    assert len(rows) == len(scores) == n
    assert rows[0]["trained"] == "0" and rows[-1]["trained"] == "1"
    assert np.isnan(scores[0]) and np.isfinite(scores[-1])


def test_cli_runs(port_scan_pcap, tmp_path, capsys):
    main(["score", str(port_scan_pcap), "--fm-grace", "40", "--ad-grace", "120",
          "--out", str(tmp_path / "run.csv"), "--save-model", str(tmp_path / "m.pkl")])
    n = sum(1 for _ in PcapSource(port_scan_pcap))
    out = capsys.readouterr().out
    assert f"scored={n - 160}" in out and (tmp_path / "m.pkl").exists()
