"""Tests for the baseline interface and the compare runner (owner: Harsh)."""

import csv

import numpy as np

from baselines import score_packets
from baselines.rules import RuleDetector
from nids.capture import Packet, PcapSource


def pkt(t, src="10.10.0.20", dport=80):
    return Packet(t, "02:00:00:00:00:0a", "02:00:00:00:00:0b", src, "10.10.0.10", 40000, dport, "tcp", 100)


def test_score_packets_from_tuple_detector():
    scores = score_packets(RuleDetector(), [pkt(i * 0.1) for i in range(20)])
    assert scores.shape == (20,) and set(np.unique(scores)) <= {0.0, 1.0}


def test_score_packets_from_scalar_detector():
    class Flat:
        def process(self, p):
            return 0.7
    assert np.allclose(score_packets(Flat(), [pkt(0)]), [0.7])


def test_compare_runs_all_detectors(port_scan_pcap, tmp_path):
    from eval.compare import run

    # labels aligned to the pcap: scan packets (src 10.10.0.66) are attacks
    pkts = list(PcapSource(port_scan_pcap))
    labels = tmp_path / "l.csv"
    with open(labels, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(("index", "ts", "label", "run_id"))
        for i, p in enumerate(pkts):
            atk = p.src_ip == "10.10.0.66"
            w.writerow((i, p.ts, int(atk), "scan-1" if atk else ""))

    res = run(str(port_scan_pcap), str(labels), None, None, None,
              threshold=1.0, hold_out=None, benign_seconds=5, fm_grace=40, ad_grace=120)
    assert set(res) == {"kitsune", "rules"}          # no RF without training data
    assert res["kitsune"]["roc_auc"] > 0.9
    assert res["rules"]["attack_packets"] == 300
    for name, block in res.items():
        assert block["detector"] == name


def test_compare_includes_rf_with_training_data(port_scan_pcap, tmp_path):
    from eval.compare import run

    pkts = list(PcapSource(port_scan_pcap))
    labels = tmp_path / "l.csv"
    with open(labels, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(("index", "ts", "label", "run_id"))
        for i, p in enumerate(pkts):
            atk = p.src_ip == "10.10.0.66"
            w.writerow((i, p.ts, int(atk), "scan-1" if atk else ""))

    # training features: reuse the pcap's own features so shapes line up
    from nids.features import FeatureExtractor
    fe = FeatureExtractor()
    feats = np.array([fe.process(p) for p in pkts])
    np.save(tmp_path / "f.npy", feats)

    res = run(str(port_scan_pcap), str(labels), str(tmp_path / "f.npy"),
              str(tmp_path / "f.npy"), str(labels), threshold=1.0, hold_out=None,
              benign_seconds=5, fm_grace=40, ad_grace=120)
    assert "rf" in res and 0.0 <= res["rf"]["roc_auc"] <= 1.0
