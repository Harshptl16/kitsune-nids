"""Choose the alert threshold from benign scores (owner: Vrajkumar).

Anomaly scores are skewed: most packets score near zero, a few much higher.
Working in log space makes the benign distribution closer to normal, so the
threshold is a high quantile of log(score) on a benign validation capture:

    th = Threshold.fit(benign_scores, quantile=0.999)
    th.is_anomalous(score)        # True above the threshold
    th.save("data/threshold.json"); Threshold.load(...)

Fit on a validation capture recorded on a different day from training and
never on test data, or the reported false-positive rate is too optimistic.
"""

from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np

FLOOR = 1e-12  # log(0) guard


@dataclass(frozen=True)
class Threshold:
    value: float          # raw score threshold
    quantile: float       # which quantile of benign log-scores it came from
    n_benign: int         # how many benign scores it was fitted on

    @classmethod
    def fit(cls, benign_scores, quantile: float = 0.999) -> Threshold:
        s = np.asarray(benign_scores, dtype=float)
        s = s[np.isfinite(s)]
        if len(s) < 100:
            raise ValueError(f"need at least 100 benign scores, got {len(s)}")
        if not 0.5 <= quantile < 1.0:
            raise ValueError("quantile must be in [0.5, 1)")
        log_q = float(np.quantile(np.log(np.maximum(s, FLOOR)), quantile))
        return cls(value=math.exp(log_q), quantile=quantile, n_benign=len(s))

    def is_anomalous(self, score: float) -> bool:
        return score > self.value

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(asdict(self), indent=2))

    @classmethod
    def load(cls, path: str | Path) -> Threshold:
        return cls(**json.loads(Path(path).read_text()))
