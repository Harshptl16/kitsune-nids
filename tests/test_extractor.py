"""Tests for the stream table and feature extractor (owner: Krishkumar)."""

import numpy as np
import pytest

from nids.capture import Packet, PcapSource
from nids.config import extractor_kwargs, load_config
from nids.features import FeatureExtractor

MAC_C, MAC_S, MAC_ATK = "02:00:00:00:00:0a", "02:00:00:00:00:0b", "02:00:00:00:00:66"


def pkt(t, src, dst, sport=40000, dport=80, length=200, src_mac=MAC_C, proto="tcp"):
    return Packet(t, src_mac, MAC_S, src, dst, sport, dport, proto, length)


def idx(fe, name):
    return fe.feature_names().index(name)


def test_shape_and_names():
    fe = FeatureExtractor()
    names = fe.feature_names()
    assert fe.n_features == 115 == len(names) == len(set(names))
    v = fe.process(pkt(0.0, "10.0.0.1", "10.0.0.2"))
    assert v.shape == (115,) and np.all(np.isfinite(v))


def test_config_builds_same_extractor():
    fe = FeatureExtractor(**extractor_kwargs(load_config()))
    assert fe.n_features == 115


def test_channel_matches_brute_force():
    """HH weight/mean at every lambda equal a from-scratch damped sum."""
    rng = np.random.default_rng(0)
    fe = FeatureExtractor()
    t, events = 0.0, []
    for _ in range(400):
        t += rng.exponential(0.02)
        size = int(rng.integers(60, 1500))
        events.append((t, size))
        v = fe.process(pkt(t, "10.0.0.1", "10.0.0.2", length=size))
    for lam in fe.lams:
        f = np.array([2.0 ** (-lam * (t - ti)) for ti, _ in events])
        x = np.array([s for _, s in events], dtype=float)
        assert v[idx(fe, f"HH_L{lam:g}_w")] == pytest.approx(f.sum(), rel=1e-6)
        assert v[idx(fe, f"HH_L{lam:g}_mean")] == pytest.approx((f * x).sum() / f.sum(), rel=1e-6)


def test_jitter_learns_regular_interval():
    fe = FeatureExtractor()
    for i in range(500):
        v = fe.process(pkt(i * 0.1, "10.0.0.1", "10.0.0.2"))
    assert v[idx(fe, "HHjit_L1_mean")] == pytest.approx(0.1, rel=0.02)
    assert v[idx(fe, "HHjit_L1_std")] < 0.02


def test_reverse_direction_feeds_2d_stats():
    fe = FeatureExtractor()
    for i in range(50):
        fe.process(pkt(i * 0.1, "10.0.0.1", "10.0.0.2", length=100))
        v = fe.process(pkt(i * 0.1 + 0.05, "10.0.0.2", "10.0.0.1", 80, 40000, length=1000))
    # magnitude combines both directions' means: sqrt(1000^2 + 100^2)
    assert v[idx(fe, "HH_L1_mag")] == pytest.approx(np.hypot(1000, 100), rel=1e-3)


def test_port_scan_creates_fresh_sockets(port_scan_pcap):
    fe = FeatureExtractor()
    rows = [(p, fe.process(p)) for p in PcapSource(port_scan_pcap)]
    w = idx(fe, "HpHp_L0.01_w")
    benign = [v[w] for p, v in rows if p.src_ip == "10.10.0.20"]
    scan = [v[w] for p, v in rows if p.src_ip == "10.10.0.66"]
    assert benign[-1] > 50          # long-lived HTTP socket
    assert max(scan) == pytest.approx(1.0, abs=1e-6)  # every probe is a new socket


def test_arp_spoof_shows_as_new_mac_ip_stream():
    fe = FeatureExtractor()
    for i in range(100):  # the real gateway talks for 10 s
        fe.process(Packet(i * 0.1, "02:00:00:00:00:01", MAC_C, "10.10.0.1", "10.10.0.20",
                          -1, -1, "arp" if i % 10 == 0 else "ip", 120))
    v = fe.process(Packet(10.0, MAC_ATK, MAC_C, "10.10.0.1", "10.10.0.20", -1, -1, "arp", 42))
    assert v[idx(fe, "MI_L0.01_w")] == pytest.approx(1.0)   # attacker MAC + gateway IP: never seen
    assert v[idx(fe, "H_L0.01_w")] > 50                    # the IP itself is well known


def test_pruning_drops_idle_streams():
    fe = FeatureExtractor(prune_every=10**9)
    for i in range(20):
        fe.process(pkt(0.0, f"10.0.1.{i}", "10.0.0.2"))
    before = len(fe.table)
    removed = fe.table.prune(10_000.0)  # long after everyone went quiet
    assert removed == before and len(fe.table) == 0 and not fe.table.covs


def test_max_streams_cap():
    fe = FeatureExtractor(prune_every=10**9, max_streams=50)
    for i in range(200):
        fe.process(pkt(i * 0.001, f"10.1.{i // 256}.{i % 256}", "10.0.0.2", sport=1000 + i))
    assert len(fe.table) <= 50 + 10  # cap enforced on the next tick after exceeding


def test_repeatable(port_scan_pcap):
    def run():
        fe = FeatureExtractor()
        return np.array([fe.process(p) for p in PcapSource(port_scan_pcap)])

    assert np.array_equal(run(), run())
