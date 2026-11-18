"""Read packets from a .pcap or .pcapng file (owner: Vrajkumar).

Usage:
    for pkt in PcapSource("capture.pcap"):
        ...
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import dpkt

from .packet import Packet, parse_ethernet

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


class PcapSource:
    def __init__(self, path: str | Path, limit: int | None = None):
        self.path = Path(path)
        self.limit = limit
        self.skipped = 0  # frames that could not be decoded

    def __iter__(self) -> Iterator[Packet]:
        with open(self.path, "rb") as fh:
            magic = fh.read(4)
            fh.seek(0)
            reader = dpkt.pcapng.Reader(fh) if magic == PCAPNG_MAGIC else dpkt.pcap.Reader(fh)
            if reader.datalink() != dpkt.pcap.DLT_EN10MB:
                raise ValueError(
                    f"{self.path}: link type {reader.datalink()} not supported; "
                    "capture on an Ethernet interface (not 'any')"
                )
            count = 0
            for ts, buf in reader:
                pkt = parse_ethernet(float(ts), buf)
                if pkt is None:
                    self.skipped += 1
                    continue
                yield pkt
                count += 1
                if self.limit is not None and count >= self.limit:
                    return
