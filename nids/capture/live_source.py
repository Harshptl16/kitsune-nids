"""Read packets live from a network interface (owner: Vrajkumar).

Scapy sniffs in a background thread and pushes raw frames into a bounded queue;
the iterator parses them with the same parser as PcapSource. If the detector
falls behind and the queue fills, frames are counted in `dropped` instead of
blocking the sniffer, so the evaluation can report drops honestly.

Needs root (or CAP_NET_RAW) on the sensor:
    sudo -E python -m eval.replay --live enp0s8
"""

from __future__ import annotations

import queue
import threading
from collections.abc import Iterator

from .packet import Packet, parse_ethernet

_STOP = object()


class LiveSource:
    def __init__(self, iface: str, bpf_filter: str | None = None,
                 max_queue: int = 100_000, limit: int | None = None):
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.limit = limit
        self.dropped = 0
        self.skipped = 0
        self._q: queue.Queue = queue.Queue(maxsize=max_queue)
        self._sniffer = None
        self._stop = threading.Event()

    def _on_frame(self, frame) -> None:
        try:
            self._q.put_nowait((float(frame.time), bytes(frame), len(frame)))
        except queue.Full:
            self.dropped += 1

    def start(self) -> None:
        from scapy.all import AsyncSniffer  # imported lazily: slow import, needs privileges

        self._sniffer = AsyncSniffer(iface=self.iface, filter=self.bpf_filter,
                                     prn=self._on_frame, store=False)
        self._sniffer.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sniffer is not None:
            self._sniffer.stop()
        self._q.put(_STOP)

    def __iter__(self) -> Iterator[Packet]:
        if self._sniffer is None:
            self.start()
        count = 0
        try:
            while not self._stop.is_set():
                try:
                    item = self._q.get(timeout=0.5)
                except queue.Empty:
                    continue
                if item is _STOP:
                    return
                ts, buf, length = item
                pkt = parse_ethernet(ts, buf, length)
                if pkt is None:
                    self.skipped += 1
                    continue
                yield pkt
                count += 1
                if self.limit is not None and count >= self.limit:
                    return
        finally:
            if self._sniffer is not None and not self._stop.is_set():
                self._sniffer.stop()
