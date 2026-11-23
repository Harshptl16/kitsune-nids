# Running the detector (owner: Harsh)

Three ways to run, from quickest to the real demo.

## 1. Score a recorded capture (offline, repeatable)

Train on the start of a benign-then-attack capture and score the rest:

```bash
python -m nids.cli score data/benign_then_scan.pcap --out data/run.scores.csv
```

Output is one row per packet with its anomaly score. Good for tuning and for the evaluation table.

## 2. Replay a capture through the full alert chain

Same scoring, but it also raises alerts and writes them to the store the dashboard reads:

```bash
python -m nids.live --pcap data/benign_then_scan.pcap --threshold 0.4 --store data/live.sqlite
```

Pick the threshold from a benign run first (see below). Alerts print as they fire and land in `data/live.sqlite`.

## 3. Live on the sensor (the demo)

Train once on a benign capture and save the model, so the demo starts detecting immediately:

```bash
# one-time: train on benign day 1 and save the model
python -m nids.live --pcap data/benign_day1.pcap --train-only --save-model data/model.pkl

# fit a threshold on a benign validation capture
python -m nids.cli score data/benign_day2.pcap --out data/val.scores.csv
python - <<'PY'
import numpy as np
from nids.detect import Threshold
s = np.loadtxt("data/val.scores.csv", delimiter=",", skiprows=1, usecols=2)
print(Threshold.fit(s[np.isfinite(s)], 0.999).value)
PY

# demo: live, pre-trained, alerting to the store the dashboard reads
sudo .venv/bin/python -m nids.live --iface enp0s3 --load-model data/model.pkl \
    --threshold <value from above> --store data/live.sqlite
```

Live capture needs root (or `CAP_NET_RAW`). Press Ctrl+C to stop; alerts so far stay in the store.

## Settings

Defaults come from `configs/default.yaml` (`fm_grace`, `ad_grace`, threshold quantile, debounce `k`/`n`). Override per run with `--fm-grace`, `--ad-grace`, `--threshold`, `--k`, `--n`.

## Safety note

`--load-model` reads a pickled model, which can run code. Only load model files your team created.
