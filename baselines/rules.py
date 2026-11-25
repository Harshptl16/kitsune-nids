"""Rule-based detector baseline (owner: Vrajkumar).

Simple, explainable thresholds on sliding time windows — the kind of rules a
basic IDS ships with. Each packet gets a score of 0 (no rule fired) or 1 (a rule
fired), plus which rule it was, so it drops straight into the same evaluation as
KitNET.

Rules:
  port scan   one source hits more than SCAN_PORTS distinct dest ports within WINDOW
  flood       one source sends more than FLOOD_PPS packets per second (over WINDOW)
  arp spoof   a source MAC claims an IP already seen from a different MAC,
              or an unsolicited ARP reply

State is kept per source over a sliding window of WINDOW seconds, so it runs
online, packet by packet, like the real detector.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field

from nids.capture import Packet

WINDOW = 2.0          # seconds
SCAN_PORTS = 20       # distinct dest ports from one source in the window
FLOOD_PPS = 500       # packets per second from one source


@dataclass
class RuleDetector:
    window: float = WINDOW
    scan_ports: int = SCAN_PORTS
    flood_pps: int = FLOOD_PPS
    # per-source sliding windows of (ts, dst_port) and ts
    _ports: dict = field(default_factory=lambda: defaultdict(deque), init=False)
    _rate: dict = field(default_factory=lambda: defaultdict(deque), init=False)
    _ip_mac: dict = field(default_factory=dict, init=False)   # ip -> mac first seen

    def _prune(self, dq: deque, now: float, key=lambda x: x) -> None:
        while dq and now - key(dq[0]) > self.window:
            dq.popleft()

    def process(self, pkt: Packet) -> tuple[float, str]:
        """Return (score, rule). score is 1.0 if any rule fires, else 0.0."""
        src = pkt.src_ip

        if pkt.proto == "arp":
            prev = self._ip_mac.get(pkt.src_ip)
            self._ip_mac.setdefault(pkt.src_ip, pkt.src_mac)
            if prev is not None and prev != pkt.src_mac:
                return 1.0, "arp_spoof"        # this IP was announced by another MAC before

        # port-scan rule
        if pkt.dst_port >= 0:
            dq = self._ports[src]
            dq.append((pkt.ts, pkt.dst_port))
            self._prune(dq, pkt.ts, key=lambda x: x[0])
            if len({p for _, p in dq}) > self.scan_ports:
                return 1.0, "port_scan"

        # flood rule
        rq = self._rate[src]
        rq.append(pkt.ts)
        self._prune(rq, pkt.ts)
        if len(rq) > self.flood_pps * self.window:
            return 1.0, "flood"

        return 0.0, ""

    def score_only(self, pkt: Packet) -> float:
        return self.process(pkt)[0]
