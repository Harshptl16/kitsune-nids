"""Damped incremental statistics (owner: Harsh).

Every statistic is kept for several decay rates at once, as NumPy vectors of
length L (one entry per lambda). Each update first decays the old state by

    f = 2 ** (-lambda * dt)

and then adds the new value. Nothing about past packets is stored, so memory per
stream is constant and an update is O(L).

Definitions (all per lambda):
    w   = damped count             sum_i f_i
    LS  = damped linear sum        sum_i f_i * x_i
    SS  = damped squared sum       sum_i f_i * x_i**2
    mean = LS / w
    var  = max(SS / w - mean**2, 0)

Decay multiplies w, LS and SS by the same factor, so mean and var do not change
when time passes without packets; only the weight w does.

IncStatCov tracks the relation between two 1D streams (e.g. A->B and B->A):
    on every update of one side with value x:
        r_self  = x - mean_self (mean after the update)
        SR     += r_self * r_other_last     (only once the other side has a residual)
        w3     += 1                          (same condition, both decayed first)
    cov       = SR / w3
    pcc       = cov / (std_a * std_b)       (0 when either std is 0)
    magnitude = sqrt(mean_a**2 + mean_b**2)
    radius    = sqrt(var_a + var_b)
"""

from __future__ import annotations

import numpy as np

DEFAULT_LAMBDAS = (5.0, 3.0, 1.0, 0.1, 0.01)


def _decay(lams: np.ndarray, dt: float) -> np.ndarray | None:
    """Decay factor per lambda for an elapsed time dt (None when nothing to do)."""
    if dt <= 0.0:
        return None
    return np.exp2(-lams * dt)


class IncStat:
    """1D damped statistics of one stream, for all lambdas at once."""

    __slots__ = ("lams", "w", "ls", "ss", "t_last", "r_last")

    def __init__(self, lams: np.ndarray):
        self.lams = lams
        n = len(lams)
        self.w = np.zeros(n)
        self.ls = np.zeros(n)
        self.ss = np.zeros(n)
        self.t_last: float | None = None
        self.r_last: np.ndarray | None = None  # residual x - mean of the last update

    def update(self, x: float, t: float) -> None:
        if self.t_last is not None:
            f = _decay(self.lams, t - self.t_last)
            if f is not None:
                self.w *= f
                self.ls *= f
                self.ss *= f
        # Out-of-order packets (t < t_last) are added without decay and do not
        # move the clock backwards.
        if self.t_last is None or t > self.t_last:
            self.t_last = t
        self.w += 1.0
        self.ls += x
        self.ss += x * x
        self.r_last = x - self.ls / self.w

    def weight_at(self, t: float) -> np.ndarray:
        """Weight decayed to time t (used for pruning)."""
        if self.t_last is None:
            return self.w.copy()
        f = _decay(self.lams, t - self.t_last)
        return self.w * f if f is not None else self.w.copy()

    def mean(self) -> np.ndarray:
        with np.errstate(invalid="ignore", divide="ignore"):
            m = self.ls / self.w
        return np.nan_to_num(m)

    def var(self) -> np.ndarray:
        with np.errstate(invalid="ignore", divide="ignore"):
            v = self.ss / self.w - (self.ls / self.w) ** 2
        return np.maximum(np.nan_to_num(v), 0.0)

    def std(self) -> np.ndarray:
        return np.sqrt(self.var())

    def stats_1d(self) -> np.ndarray:
        """[w, mean, std] stacked: shape (3, L)."""
        return np.stack([self.w, self.mean(), self.std()])


class IncStatCov:
    """2D damped statistics between two IncStat streams a and b."""

    __slots__ = ("a", "b", "lams", "sr", "w3", "t_last")

    def __init__(self, a: IncStat, b: IncStat):
        self.a = a
        self.b = b
        self.lams = a.lams
        n = len(self.lams)
        self.sr = np.zeros(n)
        self.w3 = np.zeros(n)
        self.t_last: float | None = None

    def other(self, side: IncStat) -> IncStat:
        return self.b if side is self.a else self.a

    def update(self, side: IncStat, t: float) -> None:
        """Call right after `side.update(x, t)`."""
        other = self.other(side)
        if other.r_last is None or side.r_last is None:
            return
        if self.t_last is not None:
            f = _decay(self.lams, t - self.t_last)
            if f is not None:
                self.sr *= f
                self.w3 *= f
        if self.t_last is None or t > self.t_last:
            self.t_last = t
        self.sr += side.r_last * other.r_last
        self.w3 += 1.0

    def cov(self) -> np.ndarray:
        with np.errstate(invalid="ignore", divide="ignore"):
            c = self.sr / self.w3
        return np.nan_to_num(c)

    def stats_2d(self) -> np.ndarray:
        """[magnitude, radius, cov, pcc] stacked: shape (4, L)."""
        ma, mb = self.a.mean(), self.b.mean()
        va, vb = self.a.var(), self.b.var()
        cov = self.cov()
        denom = np.sqrt(va) * np.sqrt(vb)
        with np.errstate(invalid="ignore", divide="ignore"):
            pcc = np.where(denom > 0, cov / denom, 0.0)
        return np.stack([np.sqrt(ma * ma + mb * mb), np.sqrt(va + vb), cov, pcc])
