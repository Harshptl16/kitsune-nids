"""Generate realistic benign traffic from a client VM (owner: Bhavya).

Runs a randomised mix of everyday actions against the lab server and gateway,
with gaps drawn at random so the traffic is not perfectly periodic. Every
action is logged, so a capture can later be checked against what was generated.

    python3 lab/benign/traffic_gen.py --server 10.10.0.10 --gateway 10.10.0.1 \
        --minutes 120 --seed 1 --log lab/labels/benign_client1_day1.csv

Only uses the standard library plus the ssh/ping/curl binaries already on Ubuntu.
SSH needs key-based login to the server (ssh-copy-id labuser@10.10.0.10 once).
"""

from __future__ import annotations

import argparse
import csv
import random
import socket
import subprocess
import time
import urllib.request
from datetime import datetime, timezone

LAB_PREFIX = "10.10.0."


def http_page(a):
    with urllib.request.urlopen(f"http://{a.server}/", timeout=5) as r:
        r.read()


def http_download(a):
    # nginx serves /files/ with a few test files of 100 KB to 20 MB (see lab/README.md)
    name = random.choice(["small.bin", "medium.bin", "large.bin"])
    with urllib.request.urlopen(f"http://{a.server}/files/{name}", timeout=60) as r:
        while r.read(65536):
            pass


def dns_lookup(a):
    name = random.choice(["server.lab", "gateway.lab", "client1.lab", "client2.lab", "updates.lab"])
    try:
        socket.getaddrinfo(name, 80)
    except socket.gaierror:
        pass  # NXDOMAIN is normal traffic too


def ssh_command(a):
    cmd = random.choice(["uptime", "ls -la /var/log", "df -h", "cat /etc/os-release", "ps aux | head"])
    subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", f"{a.ssh_user}@{a.server}", cmd],
                   capture_output=True, timeout=20)


def ping(a):
    target = random.choice([a.server, a.gateway])
    subprocess.run(["ping", "-c", str(random.randint(1, 5)), "-i", "0.5", target],
                   capture_output=True, timeout=10)


# (action, relative weight)
ACTIONS = [(http_page, 40), (dns_lookup, 25), (ssh_command, 15), (ping, 12), (http_download, 8)]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--server", default="10.10.0.10")
    ap.add_argument("--gateway", default="10.10.0.1")
    ap.add_argument("--ssh-user", default="labuser")
    ap.add_argument("--minutes", type=float, default=60)
    ap.add_argument("--mean-gap", type=float, default=2.0, help="mean seconds between actions")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--log", default="benign_actions.csv")
    a = ap.parse_args(argv)

    for host in (a.server, a.gateway):
        if not host.startswith(LAB_PREFIX):
            raise SystemExit(f"refusing to run: {host} is outside the lab network {LAB_PREFIX}0/24")

    random.seed(a.seed)
    funcs, weights = zip(*ACTIONS, strict=True)
    end = time.time() + a.minutes * 60
    with open(a.log, "w", newline="") as fh:
        log = csv.writer(fh)
        log.writerow(["utc_start", "action", "seconds", "ok", "error"])
        while time.time() < end:
            fn = random.choices(funcs, weights)[0]
            start = time.time()
            ok, err = True, ""
            try:
                fn(a)
            except Exception as e:  # keep generating even if one action fails
                ok, err = False, f"{type(e).__name__}: {e}"[:200]
            log.writerow([datetime.fromtimestamp(start, timezone.utc).isoformat(), fn.__name__,
                          f"{time.time() - start:.3f}", ok, err])
            fh.flush()
            # Bursty human-like pacing: mostly short gaps, sometimes a long pause.
            gap = random.expovariate(1 / a.mean_gap)
            if random.random() < 0.05:
                gap += random.uniform(20, 90)
            time.sleep(min(gap, max(end - time.time(), 0)))


if __name__ == "__main__":
    main()
