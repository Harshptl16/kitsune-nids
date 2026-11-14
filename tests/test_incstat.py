"""Gate 1 tests for incstat (owner: Harsh).

Each incremental statistic is compared with a brute-force version that keeps
every event and recomputes the damped sums from scratch.
"""

import numpy as np
import pytest

from nids.features.incstat import DEFAULT_LAMBDAS, IncStat, IncStatCov

LAMS = np.array(DEFAULT_LAMBDAS)
TOL = 1e-6


def brute_1d(events, t_now, lam):
    """events: list of (t, x). Returns w, mean, std damped to t_now."""
    f = np.array([2.0 ** (-lam * (t_now - t)) for t, _ in events])
    x = np.array([x for _, x in events])
    w = f.sum()
    mean = (f * x).sum() / w
    var = max((f * x * x).sum() / w - mean**2, 0.0)
    return w, mean, np.sqrt(var)


def random_events(rng, n, t0=0.0):
    ts = t0 + np.cumsum(rng.exponential(0.05, n))
    xs = rng.integers(60, 1500, n).astype(float)
    return list(zip(ts, xs, strict=True))


def test_single_update():
    s = IncStat(LAMS)
    s.update(100.0, 1.0)
    w, m, sd = s.stats_1d()
    assert np.allclose(w, 1.0) and np.allclose(m, 100.0) and np.allclose(sd, 0.0)


@pytest.mark.parametrize("seed", [0, 1, 2])
def test_1d_matches_brute_force(seed):
    rng = np.random.default_rng(seed)
    events = random_events(rng, 2000)
    s = IncStat(LAMS)
    for i, (t, x) in enumerate(events):
        s.update(x, t)
        if i % 250 == 0 or i == len(events) - 1:
            w, m, sd = s.stats_1d()
            for j, lam in enumerate(LAMS):
                bw, bm, bsd = brute_1d(events[: i + 1], t, lam)
                assert w[j] == pytest.approx(bw, rel=TOL, abs=TOL)
                assert m[j] == pytest.approx(bm, rel=TOL, abs=TOL)
                assert sd[j] == pytest.approx(bsd, rel=1e-4, abs=1e-4)


def test_mean_unchanged_by_idle_time():
    s = IncStat(LAMS)
    for t, x in [(0.0, 100.0), (0.1, 300.0)]:
        s.update(x, t)
    before = s.mean().copy()
    w_later = s.weight_at(10.0)
    assert np.all(w_later < s.w)
    assert np.allclose(s.mean(), before)


def test_out_of_order_does_not_move_clock_back():
    s = IncStat(LAMS)
    s.update(100.0, 5.0)
    s.update(100.0, 4.0)
    assert s.t_last == 5.0
    assert np.allclose(s.w, 2.0)


def brute_cov(events, t_now, lam):
    """events: list of (t, side, x), side in {0, 1}.

    Recomputes each residual with a brute-force mean, then the damped mean of
    residual products, exactly as IncStatCov defines it.
    """
    hist = {0: [], 1: []}
    last_r = {0: None, 1: None}
    prods = []  # (t, r_self * r_other)
    for t, side, x in events:
        hist[side].append((t, x))
        _, m, _ = brute_1d(hist[side], t, lam)
        r = x - m
        if last_r[1 - side] is not None:
            prods.append((t, r * last_r[1 - side]))
        last_r[side] = r
    f = np.array([2.0 ** (-lam * (t_now - t)) for t, _ in prods])
    p = np.array([p for _, p in prods])
    return (f * p).sum() / f.sum()


@pytest.mark.parametrize("seed", [3, 4])
def test_cov_matches_brute_force(seed):
    rng = np.random.default_rng(seed)
    n = 600
    ts = np.cumsum(rng.exponential(0.05, n))
    sides = rng.integers(0, 2, n)
    xs = rng.integers(60, 1500, n).astype(float)
    events = list(zip(ts, sides, xs, strict=True))

    a, b = IncStat(LAMS), IncStat(LAMS)
    cov = IncStatCov(a, b)
    for t, side, x in events:
        s = a if side == 0 else b
        s.update(x, t)
        cov.update(s, t)

    t_end = events[-1][0]
    got = cov.cov()
    for j, lam in enumerate(LAMS):
        assert got[j] == pytest.approx(brute_cov(events, t_end, lam), rel=1e-6, abs=1e-6)


def test_2d_magnitude_radius_pcc_bounds():
    rng = np.random.default_rng(5)
    a, b = IncStat(LAMS), IncStat(LAMS)
    cov = IncStatCov(a, b)
    for t in np.cumsum(rng.exponential(0.05, 500)):
        s = a if rng.random() < 0.5 else b
        s.update(float(rng.integers(60, 1500)), t)
        cov.update(s, t)
    mag, rad, c, pcc = cov.stats_2d()
    assert np.allclose(mag, np.sqrt(a.mean() ** 2 + b.mean() ** 2))
    assert np.allclose(rad, np.sqrt(a.var() + b.var()))
    assert np.all(np.isfinite(pcc))
