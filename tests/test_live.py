"""Tests for the live/replay runner (owner: Harsh)."""

import argparse

from nids.capture import PcapSource
from nids.detect import AlertStore
from nids.live import run


def args(**kw):
    base = dict(pcap=None, iface=None, filter=None, store=None, threshold=None, k=5, n=50,
                sample_every=10, fm_grace=40, ad_grace=120, save_model=None, load_model=None,
                train_only=False, limit=None, progress_every=0, config=None)
    base.update(kw)
    return argparse.Namespace(**base)


def test_replay_scores_and_alerts(port_scan_pcap, tmp_path):
    store = tmp_path / "live.sqlite"
    n = sum(1 for _ in PcapSource(port_scan_pcap))
    c = run(args(pcap=str(port_scan_pcap), store=store, threshold=1.0, sample_every=5))
    assert c["packets"] == n
    assert c["scored"] == n - 160          # minus (40 + 120) training packets
    assert c["alerts"] >= 1

    s = AlertStore(store)
    alerts = s.recent_alerts()
    assert alerts and alerts[0]["top_sources"][0][0] == "10.10.0.66"  # the attacker
    assert len(s.scores_since(0)) > 0      # score samples were written
    s.close()


def test_no_threshold_scores_without_alerting(port_scan_pcap):
    n = sum(1 for _ in PcapSource(port_scan_pcap))
    c = run(args(pcap=str(port_scan_pcap)))
    assert c["scored"] == n - 160 and c["alerts"] == 0


def test_train_only_saves_model(port_scan_pcap, tmp_path):
    model = tmp_path / "m.pkl"
    run(args(pcap=str(port_scan_pcap), train_only=True, save_model=model))
    assert model.exists()


def test_load_model_scores_from_first_packet(port_scan_pcap, tmp_path):
    model = tmp_path / "m.pkl"
    run(args(pcap=str(port_scan_pcap), train_only=True, save_model=model))
    # with a pre-trained model, every packet of a new run is scored (no grace period)
    n = sum(1 for _ in PcapSource(port_scan_pcap))
    c = run(args(pcap=str(port_scan_pcap), load_model=model, threshold=1.0))
    assert c["scored"] == c["packets"] == n
    assert c["alerts"] >= 1
