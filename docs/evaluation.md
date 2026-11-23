# Producing the evaluation table (owner: Rajbeer)

How the numbers in the report get made, end to end, from a recorded test capture.

## 1. Score the capture

```bash
python -m nids.cli score data/test.pcap --out data/test.scores.csv
```

(Also writes `data/test.meta.csv` for labelling.)

## 2. Label each packet

Uses the attack log the scripts wrote during the run:

```bash
python -m eval.label data/test.meta.csv lab/labels/attack_log.csv --out data/test.labels.csv
```

## 3. Evaluate, once per detector/attack

```bash
python -m eval.evaluate --scores data/test.scores.csv --labels data/test.labels.csv \
    --threshold 0.4 --benign-seconds 7200 --out results/kitsune_synscan.json
```

Name each output `<detector>_<attack>.json`; the report reads the detector and attack from the file name (or pass them inside the JSON). Repeat for the Random Forest and rule baselines (Phase 5) and for each attack type.

## 4. Build the table

```bash
python -m eval.report results/*.json --out results/table
```

This prints the Markdown table and writes `results/table.md` and `results/table.csv`:

| Detector | Attack | TPR | FPR | AUC | Detected | Median TTD (s) | False/h |
|---|---|---|---|---|---|---|---|
| kitsune | synscan | … | … | … | … | … | … |
| rules | synscan | … | … | … | … | … | … |

Paste `table.md` straight into the report. Every cell traces back to a JSON from step 3, so results are reproducible from the captures.

## What each metric means

- **TPR / FPR** at the chosen threshold: caught attacks / false alarms.
- **AUC**: threshold-free separation; 1.0 is perfect, 0.5 is chance.
- **Detected**: attack runs that raised at least one alert.
- **Median TTD**: seconds from attack start to first alert.
- **False/h**: false alerts per hour of benign traffic — the number to keep low.
