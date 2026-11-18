"""Packet record and Ethernet parser shared by every source (owner: Vrajkumar).

Both the pcap reader and the live sniffer turn raw Ethernet frames into the same
small `Packet` record, so the feature extractor never sees library objects.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass

import dpkt

NO_PORT = -1


@dataclass(frozen=True, slots=True)
class Packet:
    ts: float          # seconds since epoch (capture time)
    src_mac: str
    dst_mac: str
    src_ip: str        # IPv4/IPv6 text; ARP sender/target IP; MAC when no IP layer
    dst_ip: str
    src_port: int      # NO_PORT when the protocol has no ports
    dst_port: int
    proto: str         # "tcp" | "udp" | "icmp" | "icmp6" | "arp" | "ip" | "other"
    length: int        # frame length in bytes


def mac_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _ip_str(raw: bytes) -> str:
    if len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, raw)
    return socket.inet_ntop(socket.AF_INET6, raw)


def parse_ethernet(ts: float, buf: bytes, length: int | None = None) -> Packet | None:
    """Parse one Ethernet frame. Returns None for frames we cannot decode."""
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except (dpkt.UnpackError, dpkt.NeedData):
        return None

    src_mac, dst_mac = mac_str(eth.src), mac_str(eth.dst)
    frame_len = length if length is not None else len(buf)
    data = eth.data

    if isinstance(data, dpkt.arp.ARP):
        return Packet(ts, src_mac, dst_mac, _ip_str(data.spa), _ip_str(data.tpa),
                      NO_PORT, NO_PORT, "arp", frame_len)

    if isinstance(data, (dpkt.ip.IP, dpkt.ip6.IP6)):
        src_ip, dst_ip = _ip_str(data.src), _ip_str(data.dst)
        l4 = data.data
        if isinstance(l4, dpkt.tcp.TCP):
            return Packet(ts, src_mac, dst_mac, src_ip, dst_ip, l4.sport, l4.dport, "tcp", frame_len)
        if isinstance(l4, dpkt.udp.UDP):
            return Packet(ts, src_mac, dst_mac, src_ip, dst_ip, l4.sport, l4.dport, "udp", frame_len)
        if isinstance(l4, dpkt.icmp.ICMP):
            return Packet(ts, src_mac, dst_mac, src_ip, dst_ip, NO_PORT, NO_PORT, "icmp", frame_len)
        if isinstance(l4, dpkt.icmp6.ICMP6):
            return Packet(ts, src_mac, dst_mac, src_ip, dst_ip, NO_PORT, NO_PORT, "icmp6", frame_len)
        return Packet(ts, src_mac, dst_mac, src_ip, dst_ip, NO_PORT, NO_PORT, "ip", frame_len)

    # No IP layer (LLDP, STP, ...): use MACs as addresses so the frame still counts.
    return Packet(ts, src_mac, dst_mac, src_mac, dst_mac, NO_PORT, NO_PORT, "other", frame_len)
