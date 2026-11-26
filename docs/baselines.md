# Baselines and detector comparison (owner: Harsh)

KitNET is an anomaly detector. To show it earns its place, we compare it with two baselines on the same captures. This is the "more than a paper reproduction" part of the project.

## The three detectors

| Detector | Type | Trains on | Idea |
|---|---|---|---|
| KitNET | anomaly (unsupervised) | benign only | high reconstruction error = unusual |
| Random Forest | supervised | labelled benign + some attacks | learns attack patterns it has seen |
| Rules | unsupervised | nothing | explainable thresholds (scan / flood / spoof) |

## The headline experiment: unseen attack

The Random Forest is trained with one attack **held out** (e.g. ARP spoofing), then tested on it:

```bash
python -m eval.compare --pcap data/test.pcap --labels data/test.labels.csv \
    --features data/test.features.npy \
    --train-features data/train.features.npy --train-labels data/train.labels.csv \
    --hold-out arpspoof --threshold 0.4 --benign-seconds 7200 --out-dir results/
```

The forest catches the attacks it trained on but misses the unseen one, while KitNET — which never needed attack labels — still flags it. That is the argument for anomaly detection, shown with our own numbers.

## Building the comparison table

`eval.compare` writes one JSON per detector into `--out-dir`. Feed them to the report builder:

```bash
python -m eval.report results/*.json --out results/table
```

| Detector | Attack | TPR | FPR | AUC | Detected | Median TTD (s) | False/h |
|---|---|---|---|---|---|---|---|
| kitsune | arpspoof | … | … | … | … | … | … |
| rf | arpspoof | … | … | … | … | … | … |
| rules | arpspoof | … | … | … | … | … | … |

## Files

- `baselines/dataset.py` — build labelled X/y matrices, with an attack held out (Krishkumar)
- `baselines/rules.py` — rule-based detector (Vrajkumar)
- `baselines/random_forest.py` — Random Forest on the 115 features (Rajbeer)
- `baselines/__init__.py` — common `score_packets` interface (Krishkumar)
- `eval/compare.py` — run all three on one capture (Harsh)
- `lab/benign_surprise.py` — benign-but-unusual events, to measure false alerts (Bhavya)

The Random Forest needs scikit-learn: `pip install -e ".[dev]"` installs it.
