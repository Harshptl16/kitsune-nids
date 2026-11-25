"""Generate unusual-but-benign events to measure false alerts (owner: Bhavya).

A good detector flags attacks, not merely anything new. These are legitimate
activities that still look unusual — a large backup transfer, a new device joining,
a burst of DNS — run with NO attack. Any alert during these is a false positive,
which is the honest other half of the evaluation.

    python3 lab/benign_surprise.py --server 10.10.0.10 --event backup
    python3 lab/benign_surprise.py --server 10.10.0.10 --event all --log lab/labels/benign_surprise.csv

Like the attack scripts, it refuses to touch anything outside the lab network, and
logs each event so the evaluation knows these windows are benign (label 0).
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import socket
import subprocess
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

LAB_NET = ipaddress.ip_network("10.10.0.0/24")
LABELS_DIR = Path(__file__).resolve().parent / "labels"


def in_lab(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr) in LAB_NET
    except ValueError:
        return False


def big_download(server: str) -> None:
    """A large legitimate transfer (looks like a backup)."""
    with urllib.request.urlopen(f"http://{server}/files/large.bin", timeout=120) as r:
        while r.read(1 << 16):
            pass


def dns_burst(server: str) -> None:
    """A burst of DNS lookups, as a page with many resources would cause."""
    for i in range(200):
        try:
            socket.getaddrinfo(f"host{i}.lab", 80)
        except socket.gaierror:
            pass


def ping_sweep_self(server: str) -> None:
    """A new device checking which hosts are up — benign discovery, not a scan."""
    for host in range(1, 30):
        subprocess.run(["ping", "-c", "1", "-W", "1", f"10.10.0.{host}"],
                       capture_output=True, timeout=5)


EVENTS = {"backup": big_download, "dns": dns_burst, "newhost": ping_sweep_self}


def log_event(name: str, start: float, end: float, log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    new = not log_path.exists()
    with open(log_path, "a", newline="") as fh:
        w = csv.writer(fh)
        if new:
            w.writerow(("event", "label", "start_utc", "end_utc"))
        w.writerow((name, 0,                       # label 0: these windows are benign
                    datetime.fromtimestamp(start, timezone.utc).isoformat(),
                    datetime.fromtimestamp(end, timezone.utc).isoformat()))


def run_event(name: str, server: str, log_path: Path) -> None:
    start = time.time()
    EVENTS[name](server)
    log_event(name, start, time.time(), log_path)
    print(f"benign-surprise '{name}' done in {time.time() - start:.1f}s")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--server", default="10.10.0.10")
    ap.add_argument("--event", choices=[*EVENTS, "all"], default="all")
    ap.add_argument("--log", type=Path, default=LABELS_DIR / "benign_surprise.csv")
    args = ap.parse_args(argv)
    if not in_lab(args.server):
        raise SystemExit(f"refusing to run: {args.server} is outside the lab network {LAB_NET}")
    names = list(EVENTS) if args.event == "all" else [args.event]
    for name in names:
        run_event(name, args.server, args.log)


if __name__ == "__main__":
    main()
