# kitsune-nids

An online network intrusion detector. It reads packets live or from a `.pcap`, keeps damped running statistics for every host, channel and socket, scores each packet with an ensemble of small autoencoders trained only on normal traffic, and raises an alert when the reconstruction error passes a threshold.

This is our own implementation of the idea in Kitsune ([Mirsky et al., NDSS 2018](https://www.arxiv.org/pdf/1802.09089)). We built our own virtual lab and attack scripts, and we compare against a Random Forest and a rule-based baseline.

## How it works

```
packets ──► capture ──► feature extractor ──► feature mapper ──► autoencoder ensemble ──► output AE ──► score ──► alert
(pcap/live)  Packet      115 damped stats      groups of ≤ 10     one RMSE per group                     threshold
                         per packet            features                                                  + debounce
```

1. **Capture:** each Ethernet frame becomes a small `Packet` record (time, MACs, IPs, ports, protocol, size).
2. **Extract features:** five stream types (MAC+IP, IP, channel, channel jitter, socket) are each tracked at five decay rates, from about 100 ms to 1 minute. That gives 115 numbers per packet, with no packet history stored.
3. **Score:** small autoencoders each rebuild one group of features. They're trained only on normal traffic, so attack traffic rebuilds badly, and the rebuild error is the anomaly score.
4. **Alert:** a score above the threshold raises an alert naming the hosts involved.

## Quick start

Requires Python 3.10–3.12 (3.14 also works) and Git.

```bash
git clone https://github.com/Harshptl16/kitsune-nids.git
cd kitsune-nids
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

Once the extractor and eval tools are merged:

```bash
python -m eval.benchmark --synthetic 20000                     # speed, no pcap needed
python -m eval.replay data/test.pcapng --out data/test         # 115 features per packet
sudo .venv/bin/python -m eval.replay --live enp0s3 --limit 20000 --out data/live   # live (Linux)
```

Put captures in `data/`. Git ignores that folder and all `*.pcap` / `*.pcapng` files. Shared lab captures live in the team drive, not in git.

## Layout

```
nids/capture/    Packet record, pcap and live sources          Vrajkumar
nids/features/   incstat.py                                    Harsh
                 streams.py, extractor.py                      Krishkumar
nids/model/      autoencoders, feature mapper                  Krishkumar
                 KitNET                                        Harsh
nids/detect/     threshold, alerter, SQLite store              Vrajkumar
baselines/       rules, Random Forest                          Rajbeer
eval/            replay, benchmark, labels, metrics            Rajbeer
lab/             VM setup, benign traffic, attack scripts      Bhavya
configs/         default.yaml                                  Krishkumar
tests/           one test file per module, owned with it
```

## Working on this repo

- Every change goes through a branch (`<name>/<topic>`) and a pull request; nobody commits to `main` directly.
- Make small commits that each pass `pytest`; run `ruff check .` before pushing.
- One teammate approves before merging. Review rotation: Harsh → Vrajkumar → Krishkumar → Bhavya → Rajbeer → Harsh.
- Never commit captures, trained models or credentials.

Full workflow: `CONTRIBUTING.md`.

## Team

| Member | Area |
|---|---|
| Harsh Jayeshkumar Patel | Core statistics, model integration, repo |
| Vrajkumar Yaminkumar Patel | Capture, detection, dashboard |
| Krishkumar Maheshbhai Patel | Feature extractor, autoencoders |
| Bhavya Ketan Patel | Lab, benign traffic, attack scripts |
| Rajbeer Kaur Dutta | Evaluation, baselines, CI |

University of Windsor, 2026.
