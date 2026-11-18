"""Shared test fixtures: build Ethernet frames and small pcaps in memory (owner: Vrajkumar).

Tests never depend on capture files in the repo; every pcap they read is
generated here, so CI runs anywhere.
"""

import socket

import dpkt
import pytest

MAC_A = b"\x02\x00\x00\x00\x00\x0a"
MAC_B = b"\x02\x00\x00\x00\x00\x0b"
MAC_ATK = b"\x02\x00\x00\x00\x00\x66"


def ip4(s):
    return socket.inet_aton(s)


def eth(src, dst, data, etype):
    return bytes(dpkt.ethernet.Ethernet(src=src, dst=dst, type=etype, data=data))


def tcp_frame(src_ip, dst_ip, sport, dport, payload=b"", src_mac=MAC_A, dst_mac=MAC_B, flags=dpkt.tcp.TH_ACK):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, data=payload)
    ip = dpkt.ip.IP(src=ip4(src_ip), dst=ip4(dst_ip), p=dpkt.ip.IP_PROTO_TCP, data=tcp)
    ip.len = len(ip)
    return eth(src_mac, dst_mac, ip, dpkt.ethernet.ETH_TYPE_IP)


def udp_frame(src_ip, dst_ip, sport, dport, payload=b"", src_mac=MAC_A, dst_mac=MAC_B):
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(src=ip4(src_ip), dst=ip4(dst_ip), p=dpkt.ip.IP_PROTO_UDP, data=udp)
    ip.len = len(ip)
    return eth(src_mac, dst_mac, ip, dpkt.ethernet.ETH_TYPE_IP)


def icmp_frame(src_ip, dst_ip, src_mac=MAC_A, dst_mac=MAC_B):
    icmp = dpkt.icmp.ICMP(type=8, data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"x" * 32))
    ip = dpkt.ip.IP(src=ip4(src_ip), dst=ip4(dst_ip), p=dpkt.ip.IP_PROTO_ICMP, data=icmp)
    ip.len = len(ip)
    return eth(src_mac, dst_mac, ip, dpkt.ethernet.ETH_TYPE_IP)


def arp_reply_frame(sender_ip, target_ip, sender_mac=MAC_ATK, target_mac=MAC_A):
    arp = dpkt.arp.ARP(op=dpkt.arp.ARP_OP_REPLY, sha=sender_mac, spa=ip4(sender_ip),
                       tha=target_mac, tpa=ip4(target_ip))
    return eth(sender_mac, target_mac, arp, dpkt.ethernet.ETH_TYPE_ARP)


def ipv6_udp_frame(src="fe80::1", dst="fe80::2", sport=5353, dport=5353):
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=b"hi")
    udp.ulen = len(udp)
    ip6 = dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6, src),
                       dst=socket.inet_pton(socket.AF_INET6, dst),
                       nxt=dpkt.ip.IP_PROTO_UDP, hlim=64, data=udp)
    ip6.plen = len(udp)
    return eth(MAC_A, MAC_B, ip6, dpkt.ethernet.ETH_TYPE_IP6)


def write_pcap(path, frames):
    """frames: list of (ts, bytes)."""
    with open(path, "wb") as fh:
        w = dpkt.pcap.Writer(fh, linktype=dpkt.pcap.DLT_EN10MB)
        for ts, buf in frames:
            w.writepkt(buf, ts=ts)
    return path


@pytest.fixture
def mixed_pcap(tmp_path):
    frames = [
        (1.00, tcp_frame("10.10.0.20", "10.10.0.10", 40000, 80, b"GET / HTTP/1.1\r\n\r\n")),
        (1.01, tcp_frame("10.10.0.10", "10.10.0.20", 80, 40000, b"HTTP/1.1 200 OK\r\n\r\n",
                         src_mac=MAC_B, dst_mac=MAC_A)),
        (1.02, udp_frame("10.10.0.20", "10.10.0.1", 53000, 53, b"\x00" * 30)),
        (1.03, icmp_frame("10.10.0.20", "10.10.0.10")),
        (1.04, arp_reply_frame("10.10.0.1", "10.10.0.20")),
        (1.05, ipv6_udp_frame()),
    ]
    return write_pcap(tmp_path / "mixed.pcap", frames)


@pytest.fixture
def port_scan_pcap(tmp_path):
    """Benign HTTP for 5 s, then a SYN scan of ports 1-300 from the attacker."""
    frames, t = [], 0.0
    while t < 5.0:
        frames.append((t, tcp_frame("10.10.0.20", "10.10.0.10", 40000, 80, b"x" * 200)))
        frames.append((t + 0.01, tcp_frame("10.10.0.10", "10.10.0.20", 80, 40000, b"y" * 900,
                                           src_mac=MAC_B, dst_mac=MAC_A)))
        t += 0.05
    for port in range(1, 301):
        frames.append((t, tcp_frame("10.10.0.66", "10.10.0.10", 55555, port,
                                    src_mac=MAC_ATK, flags=dpkt.tcp.TH_SYN)))
        t += 0.002
    return write_pcap(tmp_path / "scan.pcap", frames)
