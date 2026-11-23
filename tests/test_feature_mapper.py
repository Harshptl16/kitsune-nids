"""Tests for the feature mapper (owner: Krishkumar)."""

import numpy as np
import pytest

from nids.model import FeatureMapper


def blocks(rng, n_rows, sizes):
    """Columns in blocks: columns in the same block follow the same hidden factor."""
    cols = []
    for size in sizes:
        f = rng.normal(size=(n_rows, 1))
        cols.append(f + rng.normal(0, 0.05, size=(n_rows, size)))
    return np.hstack(cols)


def fit(rows, max_size):
    fm = FeatureMapper(rows.shape[1], max_size)
    for x in rows:
        fm.update(x)
    return fm


def test_correlation_matches_numpy():
    rng = np.random.default_rng(0)
    rows = blocks(rng, 500, [3, 4])
    d = fit(rows, 10).correlation_distance()
    assert np.allclose(d, 1 - np.corrcoef(rows, rowvar=False), atol=1e-8)


def test_groups_cover_every_feature_once():
    rng = np.random.default_rng(1)
    rows = blocks(rng, 400, [5, 7, 3, 9])
    groups = fit(rows, 6).build()
    flat = sorted(i for g in groups for i in g)
    assert flat == list(range(24))
    assert all(1 <= len(g) <= 6 for g in groups)


def test_recovers_correlated_blocks():
    rng = np.random.default_rng(2)
    rows = blocks(rng, 1000, [4, 4, 4])
    groups = fit(rows, 4).build()
    assert groups == [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11]]


def test_constant_features_do_not_crash():
    rng = np.random.default_rng(3)
    rows = np.hstack([blocks(rng, 200, [3]), np.ones((200, 2))])
    groups = fit(rows, 3).build()
    assert sorted(i for g in groups for i in g) == list(range(5))


def test_needs_two_rows():
    fm = FeatureMapper(3)
    fm.update(np.zeros(3))
    with pytest.raises(RuntimeError):
        fm.build()


def test_full_kitsune_width():
    rng = np.random.default_rng(4)
    rows = blocks(rng, 300, [10] * 11 + [5])
    groups = fit(rows, 10).build()
    assert sum(len(g) for g in groups) == 115
    assert max(len(g) for g in groups) <= 10
