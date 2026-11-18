"""Tests for the packet parser and pcap reader (owner: Vrajkumar)."""

import dpkt
import pytest

from conftest import write_pcap
from nids.capture import NO_PORT, PcapSource, parse_ethernet


def test_reads_every_protocol(mixed_pcap):
    pkts = list(PcapSource(mixed_pcap))
    assert [p.proto for p in pkts] == ["tcp", "tcp", "udp", "icmp", "arp", "udp"]


def test_tcp_fields(mixed_pcap):
    p = next(iter(PcapSource(mixed_pcap)))
    assert (p.src_ip, p.dst_ip, p.src_port, p.dst_port) == ("10.10.0.20", "10.10.0.10", 40000, 80)
    assert p.src_mac == "02:00:00:00:00:0a"
    assert p.ts == pytest.approx(1.00)
    assert p.length > 54


def test_arp_uses_sender_and_target_ip(mixed_pcap):
    arp = [p for p in PcapSource(mixed_pcap) if p.proto == "arp"][0]
    assert arp.src_ip == "10.10.0.1"          # the IP the sender claims
    assert arp.src_mac == "02:00:00:00:00:66"  # ...from the attacker's MAC
    assert arp.src_port == NO_PORT


def test_ipv6(mixed_pcap):
    v6 = list(PcapSource(mixed_pcap))[-1]
    assert v6.src_ip == "fe80::1" and v6.dst_port == 5353


def test_limit(mixed_pcap):
    assert len(list(PcapSource(mixed_pcap, limit=3))) == 3


def test_garbage_frame_is_skipped(tmp_path):
    path = write_pcap(tmp_path / "bad.pcap", [(0.0, b"\x00\x01")])
    src = PcapSource(path)
    assert list(src) == [] and src.skipped == 1


def test_non_ethernet_link_type_rejected(tmp_path):
    path = tmp_path / "raw.pcap"
    with open(path, "wb") as fh:
        dpkt.pcap.Writer(fh, linktype=dpkt.pcap.DLT_RAW)
    with pytest.raises(ValueError):
        list(PcapSource(path))


def test_parse_ethernet_returns_none_on_truncated():
    assert parse_ethernet(0.0, b"\x00" * 5) is None
