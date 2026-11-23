"""KitNET: the feature mapper plus an ensemble of autoencoders and an output autoencoder
(owner: Harsh).

Every row (115 features of one packet) goes through three stages over time:

    1. mapping   first `fm_grace` rows: learn which features go together
    2. training  next `ad_grace` rows:  train each group's autoencoder, then the output one
    3. scoring   every row after that:   no learning, return the anomaly score

    ensemble layer   one small autoencoder per feature group -> one RMSE each
    output layer     one autoencoder over the vector of RMSEs -> final RMSE = score

`process(x)` returns 0.0 while mapping or training, and the score afterwards,
so the same loop works for a whole capture.
"""

from __future__ import annotations

import pickle
from pathlib import Path

import numpy as np

from .autoencoder import Autoencoder
from .feature_mapper import FeatureMapper

MAPPING, TRAINING, SCORING = "mapping", "training", "scoring"


class KitNET:
    def __init__(self, n_features: int, max_group_size: int = 10, fm_grace: int = 5000,
                 ad_grace: int = 50000, hidden_ratio: float = 0.75, learning_rate: float = 0.1,
                 seed: int = 0, feature_map: list[list[int]] | None = None):
        if fm_grace < 2 and feature_map is None:
            raise ValueError("fm_grace must be >= 2 to learn a feature map")
        self.n_features = n_features
        self.max_group_size = max_group_size
        self.fm_grace = fm_grace
        self.ad_grace = ad_grace
        self.hidden_ratio = hidden_ratio
        self.lr = learning_rate
        self.rng = np.random.default_rng(seed)
        self.n_seen = 0
        self.mapper = FeatureMapper(n_features, max_group_size)
        self.groups: list[list[int]] = []
        self.ensemble: list[Autoencoder] = []
        self.output: Autoencoder | None = None
        self.stage = MAPPING
        if feature_map is not None:
            self._build(feature_map)

    def _build(self, groups: list[list[int]]) -> None:
        self.groups = [list(g) for g in groups]
        self.ensemble = [Autoencoder(len(g), self.hidden_ratio, self.lr, self.rng) for g in self.groups]
        self.output = Autoencoder(len(self.groups), self.hidden_ratio, self.lr, self.rng)
        self.stage = TRAINING
        self._train_left = self.ad_grace

    def _rmses(self, x: np.ndarray, learn: bool) -> np.ndarray:
        if learn:
            return np.array([ae.train(x[g]) for ae, g in zip(self.ensemble, self.groups, strict=True)])
        return np.array([ae.execute(x[g]) for ae, g in zip(self.ensemble, self.groups, strict=True)])

    def process(self, x: np.ndarray) -> float:
        """Learn from x while in a grace period (returns 0.0), else return its score."""
        x = np.asarray(x, dtype=float)
        self.n_seen += 1
        if self.stage == MAPPING:
            self.mapper.update(x)
            if self.mapper.count >= self.fm_grace:
                self._build(self.mapper.build())
            return 0.0
        if self.stage == TRAINING:
            self.output.train(self._rmses(x, learn=True))
            self._train_left -= 1
            if self._train_left <= 0:
                self.stage = SCORING
            return 0.0
        return self.score(x)

    def score(self, x: np.ndarray) -> float:
        """Anomaly score without learning. Only valid once training is finished."""
        if self.stage != SCORING:
            raise RuntimeError(f"model is still {self.stage}; feed more benign rows first")
        return self.output.execute(self._rmses(np.asarray(x, dtype=float), learn=False))

    def explain(self, x: np.ndarray) -> list[tuple[list[int], float]]:
        """Per-group RMSE for x, largest first: which features made the score high."""
        r = self._rmses(np.asarray(x, dtype=float), learn=False)
        order = np.argsort(r)[::-1]
        return [(self.groups[i], float(r[i])) for i in order]

    @property
    def is_trained(self) -> bool:
        return self.stage == SCORING

    def save(self, path: str | Path) -> None:
        with open(path, "wb") as fh:
            pickle.dump(self, fh)

    @staticmethod
    def load(path: str | Path) -> KitNET:
        # Only load model files you created yourselves: pickle can run code.
        with open(path, "rb") as fh:
            return pickle.load(fh)
