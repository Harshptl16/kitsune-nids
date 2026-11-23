"""A small online autoencoder (owner: Krishkumar).

One hidden layer, tied weights (the decoder reuses W transposed), sigmoid
activations, trained one sample at a time with plain SGD. Inputs are scaled to
[0, 1] with a running min/max that only moves while training.

    ae = Autoencoder(n_visible=8)
    for x in benign_rows:
        ae.train(x)          # returns the RMSE before the update
    score = ae.execute(x)    # RMSE, no learning

The RMSE between the input and its reconstruction is the anomaly signal: traffic
like the training data is rebuilt well (low RMSE), unusual traffic badly.
"""

from __future__ import annotations

import math

import numpy as np

MIN_RANGE = 1e-3   # smallest range used for scaling, as a fraction of the feature's size
CLIP = 10.0        # scaled values are kept within [-CLIP, 1 + CLIP]


def sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(z, -500, 500)))


class Autoencoder:
    def __init__(self, n_visible: int, hidden_ratio: float = 0.75, lr: float = 0.1,
                 rng: np.random.Generator | None = None):
        if n_visible < 1:
            raise ValueError("n_visible must be >= 1")
        rng = rng if rng is not None else np.random.default_rng(0)
        self.n_visible = n_visible
        self.n_hidden = max(1, math.ceil(n_visible * hidden_ratio))
        self.lr = lr
        bound = 1.0 / n_visible
        self.W = rng.uniform(-bound, bound, size=(n_visible, self.n_hidden))
        self.h_bias = np.zeros(self.n_hidden)
        self.v_bias = np.zeros(n_visible)
        self.norm_min = np.full(n_visible, np.inf)
        self.norm_max = np.full(n_visible, -np.inf)
        self.n_trained = 0

    def _scale(self, x: np.ndarray) -> np.ndarray:
        """Min-max scale to [0, 1] using the training range.

        A feature that never varied in training has range 0, and dividing by ~0
        would turn any later change into a score of ~1e12. So every range gets a
        floor (MIN_RANGE, relative to the feature's size), and scaled values are
        clipped to [-CLIP, 1 + CLIP]: far outside the training range still scores
        high, but one feature cannot swamp the rest.
        """
        lo = np.where(np.isfinite(self.norm_min), self.norm_min, 0.0)
        hi = np.where(np.isfinite(self.norm_max), self.norm_max, 0.0)
        floor = MIN_RANGE * np.maximum(np.maximum(np.abs(lo), np.abs(hi)), 1.0)
        return np.clip((x - lo) / np.maximum(hi - lo, floor), -CLIP, 1.0 + CLIP)

    def _forward(self, xs: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        h = sigmoid(xs @ self.W + self.h_bias)
        z = sigmoid(h @ self.W.T + self.v_bias)
        return h, z

    def train(self, x: np.ndarray) -> float:
        x = np.asarray(x, dtype=float)
        self.norm_min = np.minimum(self.norm_min, x)
        self.norm_max = np.maximum(self.norm_max, x)
        xs = self._scale(x)
        h, z = self._forward(xs)
        # Gradients of the cross-entropy reconstruction loss for a tied-weight
        # sigmoid autoencoder: output error, then back through the hidden layer.
        err_v = xs - z
        err_h = (err_v @ self.W) * h * (1.0 - h)
        self.W += self.lr * (np.outer(xs, err_h) + np.outer(err_v, h))
        self.h_bias += self.lr * err_h
        self.v_bias += self.lr * err_v
        self.n_trained += 1
        return float(np.sqrt(np.mean((xs - z) ** 2)))

    def execute(self, x: np.ndarray) -> float:
        if self.n_trained == 0:
            raise RuntimeError("train() the autoencoder before execute()")
        xs = self._scale(np.asarray(x, dtype=float))
        _, z = self._forward(xs)
        return float(np.sqrt(np.mean((xs - z) ** 2)))
