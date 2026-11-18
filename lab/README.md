# Lab setup (owner: Bhavya)

Six VMs on one isolated VirtualBox internal network, `labnet` (10.10.0.0/24). The address plan is in [`config/hosts.yaml`](config/hosts.yaml).

**Safety rule:** attack scripts run only inside `labnet`. No VM has a bridged adapter while attacks run, and every script refuses to target addresses outside 10.10.0.0/24.

## 1. Create the VMs

| VM | Image | RAM | vCPU |
|---|---|---|---|
| gateway | Ubuntu Server 22.04 | 1 GB | 1 |
| sensor | Ubuntu 22.04 | 4 GB | 2–4 |
| server | Ubuntu Server 22.04 | 1 GB | 1 |
| client1, client2 | Ubuntu Desktop 22.04 (or Server) | 2 GB | 1 |
| attacker | Kali Linux | 2 GB | 1 |

Keep the default NAT adapter while installing packages:

```bash
# all Ubuntu VMs
sudo apt update && sudo apt install -y tcpdump chrony curl openssh-server
# server
sudo apt install -y nginx
# gateway
sudo apt install -y dnsmasq
# sensor
sudo apt install -y python3-venv python3-pip git tcpdump
```

Then power the VMs off and run `bash lab/scripts/vbox_setup.sh` on the host.

## 2. Static addresses (netplan)

On each VM, write `/etc/netplan/01-lab.yaml` with its address from `hosts.yaml`, then `sudo netplan apply`:

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      addresses: [10.10.0.10/24]      # this VM's IP
      routes: [{to: default, via: 10.10.0.1}]
      nameservers: {addresses: [10.10.0.1], search: [lab]}
```

## 3. Gateway

```bash
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-lab.conf && sudo sysctl --system
# /etc/dnsmasq.d/lab.conf
#   domain=lab
#   address=/server.lab/10.10.0.10
#   address=/gateway.lab/10.10.0.1
#   address=/client1.lab/10.10.0.20
#   address=/client2.lab/10.10.0.21
sudo systemctl restart dnsmasq
```

Time sync: make the gateway a chrony server (`allow 10.10.0.0/24`, `local stratum 8`) and point the others at it (`server 10.10.0.1 iburst`). Attack labels depend on clocks agreeing.

## 4. Server test files

```bash
sudo mkdir -p /var/www/html/files && cd /var/www/html/files
sudo head -c 100K  /dev/urandom | sudo tee small.bin  >/dev/null
sudo head -c 2M    /dev/urandom | sudo tee medium.bin >/dev/null
sudo head -c 20M   /dev/urandom | sudo tee large.bin  >/dev/null
```

## 5. Check the sensor sees everything

On the sensor: `sudo tcpdump -i enp0s3 -n arp`. Then on client1: `ping -c 3 10.10.0.10`. The sensor must show the ARP between client1 and the server. If it doesn't, promiscuous mode is not set to "Allow All".

## 6. Record benign captures

```bash
# sensor
sudo bash lab/scripts/capture.sh benign_day1 120
# client1 and client2 at the same time (different seeds)
python3 lab/benign/traffic_gen.py --minutes 120 --seed 1 --log benign_c1_day1.csv
python3 lab/benign/traffic_gen.py --minutes 120 --seed 2 --log benign_c2_day1.csv
```

Repeat on two more days (`benign_day2`, `benign_day3`) for validation and test. Snapshot every VM before the first capture and restore before each recorded run.
