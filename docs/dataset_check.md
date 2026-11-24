# Gate 2: validating against the public Kitsune dataset (owner: Krishkumar)

Before trusting results from our own lab, we confirm our KitNET behaves like the paper's on its published data.

## Get the data

The dataset page lists nine attacks. Each gives three files; we need two:

- `<Attack>_dataset.csv` — 115 feature columns, one row per packet, no header
- `<Attack>_labels.csv` — 0 (benign) / 1 (attack), aligned row for row

Start with **ARP MitM** and **SYN DoS** (clear, well-separated attacks). The captures start with ~1 million benign packets, then the attack.

## Run the check

```bash
python -m eval.external_check --features ARP_MitM_dataset.csv --labels ARP_MitM_labels.csv
```

To try it quickly on part of the file:

```bash
python -m eval.external_check --features ARP_MitM_dataset.csv --labels ARP_MitM_labels.csv \
    --fm-grace 5000 --ad-grace 50000 --limit 200000
```

## What Gate 2 passes on

The command prints ROC AUC over the scored (post-training) rows. **Gate 2 passes when AUC is clearly above 0.9** on at least ARP MitM and SYN DoS. If it is low:

- Make sure benign rows really come first (training must see only benign).
- Give training enough rows: `--ad-grace` at least ~50,000 on the full files.
- Check the feature CSV has 115 columns and no header row.

## Why these features, not our extractor, here

The dataset ships features already extracted with the paper's AfterImage. Feeding those into our KitNET tests the model alone. Our own extractor is checked separately in Gate 1 (the brute-force tests) and against these same captures' pcaps if we want an end-to-end comparison later.
