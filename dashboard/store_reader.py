"""Read layer over the alert store for the dashboard (owner: Vrajkumar).

Kept separate from the Streamlit app so it can be tested without a browser. The
app calls these functions once a second and draws the result.
"""

from __future__ import annotations

from dataclasses import dataclass

from nids.detect import AlertStore


@dataclass
class DashboardSnapshot:
    score_times: list[float]
    scores: list[float]
    alerts: list[dict]
    threshold: float | None
    packets_sampled: int
    alert_count: int

    @property
    def status(self) -> str:
        return "ALERT" if self.open_alert else "ok"

    @property
    def open_alert(self) -> dict | None:
        # An alert with no end_ts is still active.
        for a in self.alerts:
            if a.get("end_ts") is None:
                return a
        return None


def read_snapshot(store: AlertStore, since_ts: float = 0.0, max_alerts: int = 20) -> DashboardSnapshot:
    samples = store.scores_since(since_ts)
    alerts = store.recent_alerts(max_alerts)
    threshold = alerts[0]["threshold"] if alerts else None
    times = [t for t, _ in samples]
    scores = [s for _, s in samples]
    return DashboardSnapshot(score_times=times, scores=scores, alerts=alerts,
                             threshold=threshold, packets_sampled=len(samples),
                             alert_count=len(alerts))


def summarize_sources(alert: dict, limit: int = 3) -> str:
    srcs = alert.get("top_sources", [])[:limit]
    return ", ".join(f"{ip} ({n})" for ip, n in srcs) or "unknown"
