"""Tests for the dashboard read layer (owner: Vrajkumar).

The Streamlit app (dashboard/app.py) is a thin view over these functions and
needs a browser, so it is not tested here; its logic lives in store_reader.
"""

from dashboard.store_reader import read_snapshot, summarize_sources
from nids.capture import Packet
from nids.detect import Alerter, AlertStore, Threshold


def pkt(t, src="10.10.0.66"):
    return Packet(t, "02:00:00:00:00:66", "02:00:00:00:00:0b", src, "10.10.0.10", 1, 2, "tcp", 60)


def make_store(tmp_path, closed=True):
    store = AlertStore(tmp_path / "d.sqlite")
    a = Alerter(Threshold(1.0, 0.999, 0), k=3, n=10)
    for i in range(50):
        # closed: attack ends at i=40 so the incident closes before the run ends.
        # open: attack runs to the last packet, so the incident is still open.
        over = (5 <= i < 40) if closed else (i >= 5)
        a.update(pkt(i, "10.10.0.66" if over else "10.10.0.20"), 4.0 if over else 0.1)
        if i % 5 == 0:
            store.add_score(float(i), 4.0 if over else 0.1)
    for al in a.alerts:
        store.save_alert(al)
    store.flush()
    return store


def test_snapshot_fields(tmp_path):
    snap = read_snapshot(make_store(tmp_path))
    assert snap.alert_count == 1
    assert snap.threshold == 1.0
    assert snap.packets_sampled > 0
    assert len(snap.score_times) == len(snap.scores)


def test_status_ok_when_all_alerts_closed(tmp_path):
    snap = read_snapshot(make_store(tmp_path, closed=True))
    assert snap.status == "ok" and snap.open_alert is None


def test_status_alert_when_one_is_open(tmp_path):
    snap = read_snapshot(make_store(tmp_path, closed=False))
    assert snap.status == "ALERT"
    assert snap.open_alert["top_sources"][0][0] == "10.10.0.66"


def test_scores_since_filters(tmp_path):
    store = make_store(tmp_path)
    full = read_snapshot(store, since_ts=0)
    later = read_snapshot(store, since_ts=25)
    assert len(later.scores) < len(full.scores)


def test_summarize_sources():
    assert summarize_sources({"top_sources": [("10.10.0.66", 40), ("10.10.0.20", 2)]}) == \
        "10.10.0.66 (40), 10.10.0.20 (2)"
    assert summarize_sources({"top_sources": []}) == "unknown"


def test_empty_store(tmp_path):
    snap = read_snapshot(AlertStore(tmp_path / "empty.sqlite"))
    assert snap.alert_count == 0 and snap.threshold is None and snap.status == "ok"
