"""Registry of per-stream statistics with pruning (owner: Krishkumar).

A "stream" is any key the extractor tracks, e.g. ("HH", src_ip, dst_ip).
Streams that have gone quiet are pruned once their weight, decayed with the
slowest lambda, falls below `eps`. Without this, spoofed source IPs in a flood
would grow the table without limit.
"""

from __future__ import annotations

from collections.abc import Hashable

import numpy as np

from .incstat import IncStat, IncStatCov

Key = Hashable


class StreamTable:
    def __init__(self, lams: np.ndarray, prune_every: int = 10_000,
                 eps: float = 1e-3, max_streams: int = 500_000):
        self.lams = np.asarray(lams, dtype=float)
        self.prune_every = prune_every
        self.eps = eps
        self.max_streams = max_streams
        self.stats: dict[Key, IncStat] = {}
        self.covs: dict[tuple[Key, Key], IncStatCov] = {}
        self._updates = 0
        self.pruned_total = 0

    def __len__(self) -> int:
        return len(self.stats)

    def get(self, key: Key) -> IncStat:
        s = self.stats.get(key)
        if s is None:
            s = IncStat(self.lams)
            self.stats[key] = s
        return s

    def get_cov(self, key_a: Key, key_b: Key) -> IncStatCov:
        """Covariance object for an unordered pair of streams (created on demand)."""
        pair = (key_a, key_b) if repr(key_a) <= repr(key_b) else (key_b, key_a)
        c = self.covs.get(pair)
        if c is None:
            c = IncStatCov(self.get(pair[0]), self.get(pair[1]))
            self.covs[pair] = c
        return c

    def tick(self, t: float) -> None:
        """Call once per packet; prunes every `prune_every` packets."""
        self._updates += 1
        if self._updates % self.prune_every == 0 or len(self.stats) > self.max_streams:
            self.prune(t)

    def prune(self, t: float) -> int:
        slow = int(np.argmin(self.lams))
        # Placeholders (t_last None) exist only as the silent side of a 2D pair;
        # get_cov() recreates them on demand, so they can always go.
        dead_set = {k for k, s in self.stats.items()
                    if s.t_last is None or s.weight_at(t)[slow] < self.eps}
        # Hard cap: if still too big, evict the least recently seen streams.
        if len(self.stats) - len(dead_set) > self.max_streams:
            alive = sorted((s.t_last, i, k) for i, (k, s) in enumerate(self.stats.items())
                           if k not in dead_set)
            excess = len(alive) - self.max_streams
            dead_set.update(k for _, _, k in alive[:excess])
        for k in dead_set:
            del self.stats[k]
        if dead_set:
            self.covs = {p: c for p, c in self.covs.items()
                         if p[0] not in dead_set and p[1] not in dead_set}
        self.pruned_total += len(dead_set)
        return len(dead_set)
