#!/usr/bin/env bash
# Record a labelled capture on the sensor (owner: Bhavya).
#
#   sudo bash lab/scripts/capture.sh benign_day1 120     # name, minutes
#
# Writes data/<name>.pcap and data/<name>.info.txt (start/end time, interface,
# kernel drop count). Captures are NOT committed to git: upload them to the
# team's shared drive folder "captures/".
set -euo pipefail

NAME="${1:?usage: capture.sh NAME MINUTES [IFACE]}"
MINUTES="${2:?usage: capture.sh NAME MINUTES [IFACE]}"
IFACE="${3:-enp0s3}"
OUT_DIR="data"
mkdir -p "$OUT_DIR"

ip link set "$IFACE" promisc on
START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "capturing $IFACE for $MINUTES min -> $OUT_DIR/$NAME.pcap (started $START)"

# -s 0: full frames; -B: 16 MB buffer so short floods are not dropped; Ethernet link type only.
set +e
timeout "$((MINUTES * 60))" tcpdump -i "$IFACE" -s 0 -B 16384 -w "$OUT_DIR/$NAME.pcap" 2> "$OUT_DIR/$NAME.tcpdump.log"
set -e
END=$(date -u +%Y-%m-%dT%H:%M:%SZ)

{
  echo "name: $NAME"
  echo "interface: $IFACE"
  echo "start_utc: $START"
  echo "end_utc: $END"
  grep -E "packets (captured|received|dropped)" "$OUT_DIR/$NAME.tcpdump.log" || true
} > "$OUT_DIR/$NAME.info.txt"

cat "$OUT_DIR/$NAME.info.txt"
