"""Tests for the benign-surprise generator (owner: Bhavya).

CI checks the safety guard and the benign logging — never real network events.
"""

import csv
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lab"))
import benign_surprise  # noqa: E402
from benign_surprise import EVENTS, in_lab, log_event  # noqa: E402


def test_in_lab_guard():
    assert in_lab("10.10.0.10") and not in_lab("8.8.8.8")


def test_refuses_server_outside_lab():
    with pytest.raises(SystemExit):
        benign_surprise.main(["--server", "1.1.1.1", "--event", "backup"])


def test_events_are_known():
    assert set(EVENTS) == {"backup", "dns", "newhost"}


def test_log_marks_windows_benign(tmp_path):
    log_event("backup", 100.0, 160.0, tmp_path / "s.csv")
    rows = list(csv.DictReader(open(tmp_path / "s.csv")))
    assert len(rows) == 1
    assert rows[0]["event"] == "backup"
    assert rows[0]["label"] == "0"            # these are benign, never attack
    assert rows[0]["start_utc"] and rows[0]["end_utc"]


def test_log_appends(tmp_path):
    log_event("backup", 1.0, 2.0, tmp_path / "s.csv")
    log_event("dns", 3.0, 4.0, tmp_path / "s.csv")
    assert len(list(csv.DictReader(open(tmp_path / "s.csv")))) == 2


def test_run_event_logs_without_network(tmp_path, monkeypatch):
    called = {}
    monkeypatch.setitem(EVENTS, "backup", lambda server: called.setdefault("ran", True))
    benign_surprise.run_event("backup", "10.10.0.10", tmp_path / "s.csv")
    assert called["ran"]
    assert (tmp_path / "s.csv").exists()
