"""Tests for the online autoencoder (owner: Krishkumar)."""

import numpy as np
import pytest

from nids.model import Autoencoder


def normal_rows(rng, n, dim=6):
    """Correlated 'normal' data: every feature follows one hidden factor."""
    base = rng.uniform(0.2, 0.8, size=(n, 1))
    return base + rng.normal(0, 0.02, size=(n, dim))


def test_hidden_size():
    assert Autoencoder(10).n_hidden == 8
    assert Autoencoder(1).n_hidden == 1


def test_execute_before_train_raises():
    with pytest.raises(RuntimeError):
        Autoencoder(4).execute(np.zeros(4))


def test_training_lowers_error():
    rng = np.random.default_rng(0)
    rows = normal_rows(rng, 3000)
    ae = Autoencoder(6, lr=0.1, rng=np.random.default_rng(1))
    first = np.mean([ae.train(x) for x in rows[:200]])
    for x in rows[200:]:
        ae.train(x)
    after = np.mean([ae.execute(x) for x in normal_rows(rng, 200)])
    assert after < first * 0.6


def test_anomaly_scores_higher_than_normal():
    rng = np.random.default_rng(2)
    ae = Autoencoder(6, rng=np.random.default_rng(3))
    for x in normal_rows(rng, 5000):
        ae.train(x)
    normal = [ae.execute(x) for x in normal_rows(rng, 200)]
    # Break the correlation: half the features high, half low.
    weird = [ae.execute(np.r_[np.full(3, 0.9), np.full(3, 0.1)] + rng.normal(0, 0.02, 6))
             for _ in range(200)]
    assert np.median(weird) > 3 * np.median(normal)


def test_execute_does_not_learn():
    rng = np.random.default_rng(4)
    ae = Autoencoder(6, rng=np.random.default_rng(5))
    for x in normal_rows(rng, 500):
        ae.train(x)
    w = ae.W.copy()
    lo, hi = ae.norm_min.copy(), ae.norm_max.copy()
    ae.execute(np.full(6, 100.0))
    assert np.array_equal(w, ae.W)
    assert np.array_equal(lo, ae.norm_min) and np.array_equal(hi, ae.norm_max)


def test_constant_feature_is_safe():
    ae = Autoencoder(3)
    for _ in range(50):
        r = ae.train(np.array([5.0, 5.0, 5.0]))
    assert np.isfinite(r) and np.isfinite(ae.execute(np.array([5.0, 6.0, 5.0])))
