"""Turn per-packet scores into alerts, with debounce (owner: Vrajkumar).

A single high score is often noise. An alert fires when at least `k` of the
last `n` scored packets exceed the threshold. While that condition stays true
the incident stays open (no duplicate alerts); it closes once the window
falls back below k, and the next burst opens a new alert.

    alerter = Alerter(threshold, k=5, n=50)
    for result in detector results:
        alert = alerter.update(result.packet, result.score)
        if alert: print(alert)

Each alert records the first and peak packet of the burst and which source
hosts sent the most over-threshold packets, so the dashboard can name the
likely attacker.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field

from nids.capture import Packet

from .threshold import Threshold


@dataclass
class Alert:
    start_ts: float
    peak_ts: float
    peak_score: float
    threshold: float
    top_sources: list[tuple[str, int]]        # (src_ip, over-threshold packets), most first
    top_source_macs: list[tuple[str, int]]
    packets_over: int = 0
    end_ts: float | None = None               # set when the incident closes
    id: int = 0

    def summary(self) -> str:
        who = ", ".join(f"{ip} ({n})" for ip, n in self.top_sources[:3]) or "unknown"
        return (f"ALERT #{self.id} at {self.start_ts:.3f}: peak score {self.peak_score:.3g} "
                f"(threshold {self.threshold:.3g}); sources: {who}")


@dataclass
class Alerter:
    threshold: Threshold
    k: int = 5
    n: int = 50
    _window: deque = field(default_factory=deque, init=False)
    _over_in_window: int = field(default=0, init=False)
    _open: Alert | None = field(default=None, init=False)
    _src: Counter = field(default_factory=Counter, init=False)
    _mac: Counter = field(default_factory=Counter, init=False)
    alerts: list[Alert] = field(default_factory=list, init=False)

    def __post_init__(self):
        if not 1 <= self.k <= self.n:
            raise ValueError("need 1 <= k <= n")

    def update(self, pkt: Packet, score: float) -> Alert | None:
        """Feed one scored packet. Returns an Alert only when a new incident opens."""
        over = self.threshold.is_anomalous(score)
        self._window.append(over)
        self._over_in_window += over
        if len(self._window) > self.n:
            self._over_in_window -= self._window.popleft()

        if over:
            self._src[pkt.src_ip] += 1
            self._mac[pkt.src_mac] += 1

        firing = self._over_in_window >= self.k
        if firing and self._open is None:
            self._open = Alert(start_ts=pkt.ts, peak_ts=pkt.ts, peak_score=score,
                               threshold=self.threshold.value, top_sources=[], top_source_macs=[],
                               id=len(self.alerts) + 1)
            self.alerts.append(self._open)
            self._refresh(self._open)
            return self._open
        if self._open is not None:
            if over:
                if score > self._open.peak_score:
                    self._open.peak_score, self._open.peak_ts = score, pkt.ts
                self._refresh(self._open)
            if not firing:
                self._open.end_ts = pkt.ts
                self._open = None
                self._src.clear()
                self._mac.clear()
        elif self._over_in_window == 0:
            self._src.clear()
            self._mac.clear()
        return None

    def _refresh(self, alert: Alert) -> None:
        alert.top_sources = self._src.most_common(5)
        alert.top_source_macs = self._mac.most_common(5)
        alert.packets_over = sum(self._src.values())

    @property
    def open_alert(self) -> Alert | None:
        return self._open
