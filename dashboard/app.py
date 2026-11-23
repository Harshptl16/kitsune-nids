"""Live dashboard for the demo (owner: Vrajkumar).

Reads the SQLite store the detector writes and refreshes once a second: the score
timeline with the threshold line, a status banner, and the alert table. This is
what the audience watches while the attack runs.

    pip install streamlit pandas
    streamlit run dashboard/app.py -- --store data/live.sqlite

The detector must be writing to the same --store file (see docs/running.md).
Streamlit is an optional dependency, so this file is not imported by the tests;
the tested logic lives in dashboard/store_reader.py.
"""

from __future__ import annotations

import argparse
import sys
import time

import streamlit as st

from dashboard.store_reader import read_snapshot, summarize_sources
from nids.detect import AlertStore


def get_store_path() -> str:
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", default="data/live.sqlite")
    args, _ = ap.parse_known_args(sys.argv[1:])
    return args.store


def main() -> None:
    st.set_page_config(page_title="Kitsune NIDS", layout="wide")
    st.title("Kitsune NIDS — live")
    store_path = get_store_path()
    store = AlertStore(store_path)

    refresh = st.sidebar.slider("Refresh (seconds)", 1, 10, 1)
    window = st.sidebar.number_input("Score window (seconds, 0 = all)", min_value=0, value=0)
    status = st.empty()
    chart = st.empty()
    table = st.empty()

    while True:
        since = 0.0
        snap = read_snapshot(store, since_ts=since)
        if window and snap.score_times:
            cut = snap.score_times[-1] - window
            pairs = [(t, s) for t, s in zip(snap.score_times, snap.scores, strict=True) if t >= cut]
            snap.score_times = [t for t, _ in pairs]
            snap.scores = [s for _, s in pairs]

        open_alert = snap.open_alert
        if open_alert:
            status.error(f"🚨 ALERT — peak {open_alert['peak_score']:.3g}, "
                         f"sources: {summarize_sources(open_alert)}")
        else:
            status.success("✅ Traffic normal")

        if snap.scores:
            import pandas as pd
            df = pd.DataFrame({"time": snap.score_times, "score": snap.scores})
            if snap.threshold:
                df["threshold"] = snap.threshold
            chart.line_chart(df.set_index("time"))

        if snap.alerts:
            rows = [{
                "id": a["id"],
                "start": f"{a['start_ts']:.2f}",
                "peak score": f"{a['peak_score']:.3g}",
                "packets over": a["packets_over"],
                "top sources": summarize_sources(a),
                "status": "open" if a.get("end_ts") is None else "closed",
            } for a in snap.alerts]
            table.table(rows)
        else:
            table.info("No alerts yet.")

        time.sleep(refresh)


if __name__ == "__main__":
    main()
