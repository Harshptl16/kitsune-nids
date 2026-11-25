"""Tests for the rule-based detector (owner: Vrajkumar)."""

from baselines.rules import RuleDetector
from nids.capture import Packet

MAC_A, MAC_B, MAC_ATK = "02:00:00:00:00:0a", "02:00:00:00:00:0b", "02:00:00:00:00:66"


def tcp(t, src, dport, sport=40000, src_mac=MAC_A):
    return Packet(t, src_mac, MAC_B, src, "10.10.0.10", sport, dport, "tcp", 100)


def arp(t, ip, mac):
    return Packet(t, mac, "ff:ff:ff:ff:ff:ff", ip, "10.10.0.20", -1, -1, "arp", 60)


def test_benign_traffic_scores_zero():
    d = RuleDetector()
    scores = [d.process(tcp(i * 0.1, "10.10.0.20", 80))[0] for i in range(100)]
    assert sum(scores) == 0


def test_port_scan_fires():
    d = RuleDetector(scan_ports=20)
    fired = False
    for port in range(1, 60):
        s, rule = d.process(tcp(port * 0.001, "10.10.0.66", port, src_mac=MAC_ATK))
        if s:
            assert rule == "port_scan"
            fired = True
            break
    assert fired


def test_scan_rule_respects_window():
    d = RuleDetector(scan_ports=20, window=2.0)
    # one port every second: never more than ~2 distinct ports in the 2s window
    scores = [d.process(tcp(i * 1.0, "10.10.0.66", i, src_mac=MAC_ATK))[0] for i in range(60)]
    assert sum(scores) == 0


def test_flood_fires():
    d = RuleDetector(flood_pps=500, window=2.0)
    # 2000 packets in ~1s from one source -> well over 500 pps
    fired = any(d.process(tcp(i * 0.0005, "10.10.0.66", 80, src_mac=MAC_ATK))[1] == "flood"
                for i in range(2000))
    assert fired


def test_arp_spoof_fires_on_mac_change():
    d = RuleDetector()
    assert d.process(arp(0.0, "10.10.0.1", "02:00:00:00:00:01"))[0] == 0.0   # gateway, first time
    s, rule = d.process(arp(1.0, "10.10.0.1", MAC_ATK))                       # attacker claims it
    assert s == 1.0 and rule == "arp_spoof"


def test_same_mac_same_ip_is_fine():
    d = RuleDetector()
    for t in range(10):
        s, _ = d.process(arp(float(t), "10.10.0.1", "02:00:00:00:00:01"))
        assert s == 0.0
