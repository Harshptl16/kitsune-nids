"""Random Forest baseline (owner: Rajbeer).

A supervised detector on the same 115 features, so the report can compare it with
the anomaly model. Trained on labelled rows (see baselines.dataset); the anomaly
score is the forest's predicted probability of the attack class.

The headline experiment is the *unseen attack*: train with one attack held out
(e.g. ARP spoofing), then score it. The forest does well on attacks it saw and
poorly on the unseen one — which is exactly why we prefer anomaly detection.

    from baselines.dataset import load_xy, holdout_split
    from baselines.random_forest import RandomForestBaseline
    ds = load_xy("data/test.features.npy", "data/test.labels.csv")
    train, test = holdout_split(ds, hold_out_run_prefix="arpspoof")
    rf = RandomForestBaseline().fit(ds.X[train], ds.y[train])
    scores = rf.score(ds.X[test])

Needs scikit-learn: pip install -e ".[ml]"
"""

from __future__ import annotations

import pickle
from pathlib import Path

import numpy as np


class RandomForestBaseline:
    def __init__(self, n_estimators: int = 100, max_depth: int | None = None,
                 class_weight: str = "balanced", seed: int = 0):
        from sklearn.ensemble import RandomForestClassifier
        self.clf = RandomForestClassifier(
            n_estimators=n_estimators, max_depth=max_depth,
            class_weight=class_weight, random_state=seed, n_jobs=-1)
        self._fitted = False

    def fit(self, X: np.ndarray, y: np.ndarray) -> RandomForestBaseline:
        if len(np.unique(y)) < 2:
            raise ValueError("training labels must contain both classes (0 and 1)")
        self.clf.fit(X, y)
        self._fitted = True
        # index of the attack class (1) in the fitted classes_
        self._attack_col = int(np.where(self.clf.classes_ == 1)[0][0])
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        """Anomaly score per row = P(attack). Higher = more suspicious."""
        if not self._fitted:
            raise RuntimeError("fit() before score()")
        return self.clf.predict_proba(X)[:, self._attack_col]

    def predict(self, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        return (self.score(X) > threshold).astype(int)

    def feature_importances(self, top: int = 10) -> list[tuple[int, float]]:
        imp = self.clf.feature_importances_
        order = np.argsort(imp)[::-1][:top]
        return [(int(i), float(imp[i])) for i in order]

    def save(self, path: str | Path) -> None:
        with open(path, "wb") as fh:
            pickle.dump(self, fh)

    @staticmethod
    def load(path: str | Path) -> RandomForestBaseline:
        with open(path, "rb") as fh:       # only load models your team made (pickle runs code)
            return pickle.load(fh)
