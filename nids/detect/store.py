"""SQLite store for alerts and a sample of scores (owner: Vrajkumar).

The detector writes here; the dashboard (later) only reads. SQLite needs no
server, and one file is easy to copy into the report.

    store = AlertStore("data/alerts.sqlite")
    store.add_score(ts, score)            # sampled, e.g. every 10th packet
    store.save_alert(alert)               # insert or update by alert id
    store.recent_alerts(20)
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .alerter import Alert

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    start_ts REAL NOT NULL,
    end_ts REAL,
    peak_ts REAL NOT NULL,
    peak_score REAL NOT NULL,
    threshold REAL NOT NULL,
    packets_over INTEGER NOT NULL,
    top_sources TEXT NOT NULL,
    top_source_macs TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scores (
    ts REAL NOT NULL,
    score REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS scores_ts ON scores (ts);
"""


class AlertStore:
    def __init__(self, path: str | Path = ":memory:"):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.executescript(SCHEMA)

    def save_alert(self, a: Alert) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (a.id, a.start_ts, a.end_ts, a.peak_ts, a.peak_score, a.threshold, a.packets_over,
             json.dumps(a.top_sources), json.dumps(a.top_source_macs)))
        self.db.commit()

    def add_score(self, ts: float, score: float) -> None:
        self.db.execute("INSERT INTO scores VALUES (?, ?)", (ts, score))

    def flush(self) -> None:
        self.db.commit()

    def recent_alerts(self, limit: int = 20) -> list[dict]:
        cur = self.db.execute("SELECT * FROM alerts ORDER BY start_ts DESC LIMIT ?", (limit,))
        cols = [c[0] for c in cur.description]
        out = []
        for row in cur.fetchall():
            d = dict(zip(cols, row, strict=True))
            d["top_sources"] = [tuple(x) for x in json.loads(d["top_sources"])]
            d["top_source_macs"] = [tuple(x) for x in json.loads(d["top_source_macs"])]
            out.append(d)
        return out

    def scores_since(self, ts: float) -> list[tuple[float, float]]:
        return self.db.execute("SELECT ts, score FROM scores WHERE ts >= ? ORDER BY ts", (ts,)).fetchall()

    def close(self) -> None:
        self.db.commit()
        self.db.close()
