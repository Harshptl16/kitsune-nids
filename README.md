# kitsune-nids

An online network intrusion detector. It watches packets live or from a `.pcap`, keeps damped running statistics per host, channel and socket, scores each packet with an ensemble of small autoencoders trained only on normal traffic, and raises an alert when the reconstruction error passes a threshold. It's our own implementation of the idea in Kitsune (Mirsky et al., NDSS 2018), with our own lab, attack scripts and baseline comparison.

## Status

| Phase | What | State |
|---|---|---|
| 0 | Lab, repo, CI | in progress |
| 1 | Capture + 115-feature extractor (Gate 1) | in progress |
| 2 | Feature mapper + autoencoder ensemble (Gate 2) | not started |
| 3 | Threshold, alerts, live mode (Gate 3) | not started |
| 4 | Attack scripts + labelled data | not started |
| 5 | Baselines: rules, Random Forest | not started |
| 6 | Evaluation + speed (Gate 4) | not started |
| 7 | Dashboard + demo | not started |

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest                                            # all tests
python -m eval.benchmark --synthetic 20000        # throughput, no pcap needed
python -m eval.replay data/benign_day1.pcap --out data/benign_day1   # 115 features per packet
```

## Layout

```
nids/capture/    Packet record, pcap and live sources          (Vrajkumar)
nids/features/   incstat.py (Harsh), streams.py + extractor.py (Krishkumar)
nids/model/      autoencoders, feature mapper, KitNET          (Phase 2)
nids/detect/     threshold, alerter, SQLite store              (Phase 3)
baselines/       rules, Random Forest                          (Phase 5)
eval/            replay, benchmark, labels, metrics            (Rajbeer)
lab/             VM setup, benign traffic, attack scripts      (Bhavya)
configs/         default.yaml
tests/
```

## Team

Harsh Jayeshkumar Patel · Vrajkumar Yaminkumar Patel · Krishkumar Maheshbhai Patel · Bhavya Ketan Patel · Rajbeer Kaur Dutta

University of Windsor, 2026.
