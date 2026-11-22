"""TCP/UDP port scan from the attacker VM (owner: Bhavya).

Each probe opens a new, short-lived socket, which the HpHp socket features catch.

    sudo python3 lab/attacks/portscan.py --target 10.10.0.10 --mode syn --ports 1-1024
    sudo python3 lab/attacks/portscan.py --target 10.10.0.10 --mode udp --ports 1-100 --rate 200

Modes: syn (half-open), connect (full handshake via the OS), udp. Run on Kali
inside the lab only; attack_base refuses targets outside 10.10.0.0/24.
"""

from __future__ import annotations

import argparse
import socket
import time

from attack_base import AttackRun


def parse_ports(spec: str) -> list[int]:
    out: list[int] = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return out


def syn_scan(target, ports, rate, run):
    from scapy.all import IP, TCP, send  # noqa: N811
    delay = 1.0 / rate if rate else 0.0
    for p in ports:
        send(IP(dst=target) / TCP(dport=p, flags="S"), verbose=0)
        run.sent += 1
        if delay:
            time.sleep(delay)


def connect_scan(target, ports, rate, run):
    delay = 1.0 / rate if rate else 0.0
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        try:
            s.connect((target, p))
        except OSError:
            pass
        finally:
            s.close()
        run.sent += 1
        if delay:
            time.sleep(delay)


def udp_scan(target, ports, rate, run):
    from scapy.all import IP, UDP, send  # noqa: N811
    delay = 1.0 / rate if rate else 0.0
    for p in ports:
        send(IP(dst=target) / UDP(dport=p), verbose=0)
        run.sent += 1
        if delay:
            time.sleep(delay)


SCANS = {"syn": syn_scan, "connect": connect_scan, "udp": udp_scan}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--mode", choices=SCANS, default="syn")
    ap.add_argument("--ports", default="1-1024")
    ap.add_argument("--rate", type=float, default=0, help="probes per second (0 = as fast as possible)")
    args = ap.parse_args(argv)
    ports = parse_ports(args.ports)
    with AttackRun("portscan", args.mode, target=args.target, rate=args.rate,
                   note=f"{len(ports)} ports") as run:
        SCANS[args.mode](args.target, ports, args.rate, run)


if __name__ == "__main__":
    main()
