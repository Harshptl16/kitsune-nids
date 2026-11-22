"""Shared wrapper for every attack script (owner: Bhavya).

Two jobs, both about safety and honest labels:

  1. Refuse to run unless the target is inside the lab network (10.10.0.0/24),
     so an attack can never leave for a real network by accident.
  2. Log one ground-truth row per run: attack, variant, start/end time, attacker
     MAC and IP, target, rate, run id. eval/label.py reads this to label packets.

    from attack_base import AttackRun
    with AttackRun("portscan", "syn", target="10.10.0.10", rate=500) as run:
        ... send packets ...        # run.sent += 1 as you go

Scapy sends the packets; this only guards and records them.
"""

from __future__ import annotations

import csv
import ipaddress
import socket
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

LAB_NET = ipaddress.ip_network("10.10.0.0/24")
LABELS_DIR = Path(__file__).resolve().parent.parent / "labels"
LABELS_CSV = LABELS_DIR / "attack_log.csv"
COLS = ("run_id", "attack", "variant", "start_utc", "end_utc", "attacker_ip", "attacker_mac",
        "target", "rate", "sent", "note")


def in_lab(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr) in LAB_NET
    except ValueError:
        return False


def local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.10.0.1", 1))
        return s.getsockname()[0]
    finally:
        s.close()


class AttackRun:
    def __init__(self, attack: str, variant: str, target: str, rate: float | int | str = "",
                 note: str = "", attacker_mac: str = ""):
        for t in str(target).replace(",", " ").split():
            if not in_lab(t):
                raise SystemExit(f"refusing to run: target {t} is outside the lab network {LAB_NET}")
        self.attack = attack
        self.variant = variant
        self.target = target
        self.rate = rate
        self.note = note
        self.attacker_ip = local_ip()
        self.attacker_mac = attacker_mac
        self.run_id = f"{attack}-{variant}-{uuid.uuid4().hex[:8]}"
        self.sent = 0
        self.start = None

    def __enter__(self) -> AttackRun:
        self.start = time.time()
        print(f"[{self.run_id}] {self.attack}/{self.variant} -> {self.target} "
              f"(rate={self.rate}) from {self.attacker_ip}")
        return self

    def __exit__(self, exc_type, exc, tb):
        end = time.time()
        LABELS_DIR.mkdir(parents=True, exist_ok=True)
        new = not LABELS_CSV.exists()
        with open(LABELS_CSV, "a", newline="") as fh:
            w = csv.writer(fh)
            if new:
                w.writerow(COLS)
            w.writerow([self.run_id, self.attack, self.variant,
                        datetime.fromtimestamp(self.start, timezone.utc).isoformat(),
                        datetime.fromtimestamp(end, timezone.utc).isoformat(),
                        self.attacker_ip, self.attacker_mac, self.target, self.rate, self.sent, self.note])
        print(f"[{self.run_id}] done: sent {self.sent} in {end - self.start:.1f}s -> {LABELS_CSV}")
        return False
