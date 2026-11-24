"""Baseline detectors to compare against KitNET (owner: Harsh for the interface).

Two baselines live here:
  rules.RuleDetector            unsupervised, explainable thresholds (Vrajkumar)
  random_forest.RandomForest…   supervised on the 115 features (Rajbeer)
dataset.py builds the labelled matrices they train on (Krishkumar).

A "scorer" is anything that turns packets into a per-packet score array, so the
evaluation treats KitNET, the rules and the forest the same way.
"""

from typing import Protocol

import numpy as np

from nids.capture import Packet


class PacketScorer(Protocol):
    def process(self, pkt: Packet) -> tuple[float, str] | object: ...


def score_packets(detector, packets) -> np.ndarray:
    """Run a packet-by-packet detector (e.g. RuleDetector) over packets -> score array."""
    out = []
    for pkt in packets:
        r = detector.process(pkt)
        out.append(r[0] if isinstance(r, tuple) else float(r))
    return np.array(out)


__all__ = ["PacketScorer", "score_packets"]
