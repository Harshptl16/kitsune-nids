#!/usr/bin/env bash
# Attach every lab VM to the isolated internal network "labnet" (owner: Bhavya).
# Run on the host with the VMs powered off. VM names must match those below.
#
#   bash lab/scripts/vbox_setup.sh
#
# Adapter 1 of each VM is moved to the internal network (no NAT, no bridge), so
# nothing in the lab can reach the internet or the campus network. Install
# packages BEFORE running this, or temporarily add a NAT adapter 2 and remove it after.
set -euo pipefail

NET="labnet"
VMS=(gateway sensor server client1 client2 attacker)

for vm in "${VMS[@]}"; do
  if ! VBoxManage showvminfo "$vm" >/dev/null 2>&1; then
    echo "skip: VM '$vm' not found"; continue
  fi
  VBoxManage modifyvm "$vm" --nic1 intnet --intnet1 "$NET" --cableconnected1 on
  echo "ok:   $vm -> intnet:$NET"
done

# The sensor must see frames between other hosts (ARP spoofing happens between client1 and gateway).
VBoxManage modifyvm sensor --nicpromisc1 allow-all
echo "ok:   sensor adapter 1 promiscuous = allow-all"

echo
echo "Check: no VM should have a bridged adapter during attack runs:"
for vm in "${VMS[@]}"; do
  VBoxManage showvminfo "$vm" --machinereadable 2>/dev/null | grep -E '^nic[0-9]=' | sed "s/^/  $vm: /" || true
done
