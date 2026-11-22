"""Tests for the attack-script safety wrapper (owner: Bhavya).

The attack scripts themselves need root and Scapy, so CI only tests the guard
and the ground-truth log, which is what keeps the lab safe and the labels honest.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lab" / "attacks"))
import attack_base  # noqa: E402
from attack_base import AttackRun, in_lab  # noqa: E402


def test_in_lab():
    assert in_lab("10.10.0.10") and in_lab("10.10.0.254")
    assert not in_lab("8.8.8.8") and not in_lab("192.168.1.1") and not in_lab("not-an-ip")


def test_refuses_target_outside_lab():
    with pytest.raises(SystemExit):
        AttackRun("portscan", "syn", target="8.8.8.8")


def test_refuses_if_any_target_outside_lab():
    with pytest.raises(SystemExit):
        AttackRun("arpspoof", "mitm", target="10.10.0.20,1.1.1.1")


def test_logs_ground_truth(tmp_path, monkeypatch):
    monkeypatch.setattr(attack_base, "LABELS_DIR", tmp_path)
    monkeypatch.setattr(attack_base, "LABELS_CSV", tmp_path / "attack_log.csv")
    monkeypatch.setattr(attack_base, "local_ip", lambda: "10.10.0.66")
    with AttackRun("portscan", "syn", target="10.10.0.10", rate=500) as run:
        run.sent = 1024
    import csv
    rows = list(csv.DictReader(open(tmp_path / "attack_log.csv")))
    assert len(rows) == 1
    r = rows[0]
    assert r["attack"] == "portscan" and r["target"] == "10.10.0.10"
    assert r["attacker_ip"] == "10.10.0.66" and r["sent"] == "1024"
    assert r["start_utc"] and r["end_utc"]


def test_log_appends(tmp_path, monkeypatch):
    monkeypatch.setattr(attack_base, "LABELS_DIR", tmp_path)
    monkeypatch.setattr(attack_base, "LABELS_CSV", tmp_path / "attack_log.csv")
    monkeypatch.setattr(attack_base, "local_ip", lambda: "10.10.0.66")
    for mode in ("syn", "udp"):
        with AttackRun("portscan", mode, target="10.10.0.10"):
            pass
    import csv
    assert len(list(csv.DictReader(open(tmp_path / "attack_log.csv")))) == 2
