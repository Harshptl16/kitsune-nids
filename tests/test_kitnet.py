"""Tests for KitNET (owner: Harsh)."""

import numpy as np
import pytest

from nids.model.kitnet import MAPPING, SCORING, TRAINING, KitNET


def normal_rows(rng, n, dim=20):
    """Two hidden factors drive two blocks of features."""
    a = rng.uniform(0.2, 0.8, size=(n, 1))
    b = rng.uniform(0.2, 0.8, size=(n, 1))
    half = dim // 2
    return np.hstack([a + rng.normal(0, 0.02, (n, half)), b + rng.normal(0, 0.02, (n, dim - half))])


def trained(rng, fm=200, ad=4000, dim=20):
    k = KitNET(dim, max_group_size=10, fm_grace=fm, ad_grace=ad, seed=1)
    for x in normal_rows(rng, fm + ad, dim):
        assert k.process(x) == 0.0
    return k


def test_stages_advance_on_schedule():
    rng = np.random.default_rng(0)
    k = KitNET(20, fm_grace=10, ad_grace=5)
    rows = normal_rows(rng, 16)
    stages = []
    for x in rows:
        stages.append(k.stage)
        k.process(x)
    assert stages[:10] == [MAPPING] * 10
    assert stages[10:15] == [TRAINING] * 5
    assert stages[15] == SCORING and k.is_trained


def test_score_before_training_raises():
    with pytest.raises(RuntimeError):
        KitNET(5, fm_grace=10).score(np.zeros(5))


def test_ensemble_matches_feature_groups():
    k = trained(np.random.default_rng(1))
    assert sorted(i for g in k.groups for i in g) == list(range(20))
    assert len(k.ensemble) == len(k.groups)
    assert k.output.n_visible == len(k.groups)


def test_anomalies_score_higher():
    rng = np.random.default_rng(2)
    k = trained(rng)
    normal = [k.process(x) for x in normal_rows(rng, 300)]
    odd = np.hstack([np.full((300, 10), 0.8), np.full((300, 10), 0.2)])
    odd[:, ::2] = 0.2  # breaks the correlation inside each block
    anomalous = [k.process(x) for x in odd]
    assert np.median(anomalous) > 3 * np.median(normal)


def test_scoring_does_not_learn():
    rng = np.random.default_rng(3)
    k = trained(rng)
    x = normal_rows(rng, 1)[0]
    assert k.process(x) == k.process(x) == k.score(x)


def test_explain_lists_every_group_largest_first():
    rng = np.random.default_rng(4)
    k = trained(rng)
    parts = k.explain(normal_rows(rng, 1)[0])
    errs = [e for _, e in parts]
    assert len(parts) == len(k.groups) and errs == sorted(errs, reverse=True)


def test_fixed_feature_map_skips_mapping():
    k = KitNET(4, fm_grace=0, ad_grace=3, feature_map=[[0, 1], [2, 3]])
    assert k.stage == TRAINING


def test_save_and_load(tmp_path):
    rng = np.random.default_rng(5)
    k = trained(rng)
    x = normal_rows(rng, 1)[0]
    k.save(tmp_path / "m.pkl")
    assert KitNET.load(tmp_path / "m.pkl").score(x) == pytest.approx(k.score(x))
