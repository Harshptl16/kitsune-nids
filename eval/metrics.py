"""Score a detector run against ground-truth labels (owner: Rajbeer).

Two kinds of number the report needs:

  Packet level  (needs scores + labels): ROC AUC and equal error rate, which are
                threshold-free, plus TPR/FPR at a chosen threshold.
  Event level   (needs labels + alert windows): how many attack runs raised at
                least one alert, the median time to detect, and false alerts per
                hour of benign traffic.

Pure NumPy, no scikit-learn, so it has no heavy dependency.
"""

from __future__ import annotations

import numpy as np


def roc_auc(labels, scores) -> float:
    """Probability a random attack packet scores above a random benign one (ties count half)."""
    y = np.asarray(labels, dtype=int)
    s = np.asarray(scores, dtype=float)
    keep = np.isfinite(s)
    y, s = y[keep], s[keep]
    n_pos, n_neg = int(y.sum()), int((y == 0).sum())
    if n_pos == 0 or n_neg == 0:
        return float("nan")
    order = np.argsort(s, kind="mergesort")
    ranks = np.empty(len(s))
    ranks[order] = np.arange(1, len(s) + 1)
    # Average ranks within tied score groups.
    _, inv, counts = np.unique(s, return_inverse=True, return_counts=True)
    csum = np.cumsum(counts)
    avg = {i: (csum[i] - counts[i] + 1 + csum[i]) / 2 for i in range(len(counts))}
    ranks = np.array([avg[i] for i in inv])
    return float((ranks[y == 1].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg))


def tpr_fpr(labels, scores, threshold) -> tuple[float, float]:
    y = np.asarray(labels, dtype=int)
    s = np.asarray(scores, dtype=float)
    keep = np.isfinite(s)
    y, s = y[keep], s[keep]
    pred = s > threshold
    tpr = float(pred[y == 1].mean()) if (y == 1).any() else float("nan")
    fpr = float(pred[y == 0].mean()) if (y == 0).any() else float("nan")
    return tpr, fpr


def equal_error_rate(labels, scores) -> tuple[float, float]:
    """The threshold where false-positive rate ~= false-negative rate, and that rate."""
    y = np.asarray(labels, dtype=int)
    s = np.asarray(scores, dtype=float)
    keep = np.isfinite(s)
    y, s = y[keep], s[keep]
    if not (y == 1).any() or not (y == 0).any():
        return float("nan"), float("nan")
    best = None
    for th in np.unique(s):
        tpr, fpr = tpr_fpr(y, s, th)
        gap = abs(fpr - (1 - tpr))
        if best is None or gap < best[0]:
            best = (gap, th, (fpr + (1 - tpr)) / 2)
    return float(best[1]), float(best[2])


def event_metrics(ts, labels, run_ids, alert_starts, benign_seconds: float) -> dict:
    """Detected runs, median time-to-detect, false alerts per benign hour.

    ts, labels, run_ids: aligned per-packet arrays.
    alert_starts: start timestamps of raised alerts.
    """
    ts = np.asarray(ts, dtype=float)
    labels = np.asarray(labels, dtype=int)
    run_ids = np.asarray(run_ids, dtype=object)
    alert_starts = np.sort(np.asarray(alert_starts, dtype=float))

    runs = {}
    for rid in set(run_ids[labels == 1]):
        mask = run_ids == rid
        runs[rid] = (ts[mask].min(), ts[mask].max())

    detected, delays, true_alerts = 0, [], set()
    for rid, (start, end) in runs.items():
        hit = alert_starts[(alert_starts >= start) & (alert_starts <= end + 1.0)]
        if len(hit):
            detected += 1
            delays.append(float(hit[0] - start))
            true_alerts.add(rid)
    false_alerts = sum(1 for a in alert_starts
                       if not any(s <= a <= e + 1.0 for s, e in runs.values()))
    hours = benign_seconds / 3600 if benign_seconds > 0 else float("nan")
    return {
        "attack_runs": len(runs),
        "detected_runs": detected,
        "detection_rate": detected / len(runs) if runs else float("nan"),
        "median_time_to_detect_s": float(np.median(delays)) if delays else float("nan"),
        "false_alerts": false_alerts,
        "false_alerts_per_hour": false_alerts / hours if hours and hours == hours else float("nan"),
    }
