"""Learn which features belong together, so each autoencoder sees a small related group
(owner: Krishkumar).

During the mapping grace period the mapper keeps running sums, never the rows:

    N   number of rows seen
    S   sum of each feature                     (n,)
    SS  sum of products of every feature pair   (n, n)

From those it gets the correlation matrix, turns it into a distance
(1 - correlation, so strongly correlated features are close), and clusters the
features by single linkage. Any cluster bigger than `max_group_size` is split
at its weakest link until every group fits.

Single linkage is built from the minimum spanning tree (MST) of the distance
graph: removing the k longest MST edges gives the same clusters as cutting the
single-linkage tree into k+1 pieces.
"""

from __future__ import annotations

import numpy as np


class FeatureMapper:
    def __init__(self, n_features: int, max_group_size: int = 10):
        if max_group_size < 1:
            raise ValueError("max_group_size must be >= 1")
        self.n = n_features
        self.max_group_size = max_group_size
        self.count = 0
        self.s = np.zeros(n_features)
        self.ss = np.zeros((n_features, n_features))

    def update(self, x: np.ndarray) -> None:
        x = np.asarray(x, dtype=float)
        self.count += 1
        self.s += x
        self.ss += np.outer(x, x)

    def correlation_distance(self) -> np.ndarray:
        if self.count < 2:
            raise RuntimeError("need at least 2 rows to measure correlation")
        mean = self.s / self.count
        cov = self.ss / self.count - np.outer(mean, mean)
        std = np.sqrt(np.clip(np.diag(cov), 0.0, None))
        denom = np.outer(std, std)
        with np.errstate(invalid="ignore", divide="ignore"):
            corr = np.where(denom > 0, cov / denom, 0.0)
        dist = 1.0 - np.clip(corr, -1.0, 1.0)
        np.fill_diagonal(dist, 0.0)
        return dist

    @staticmethod
    def _mst_edges(dist: np.ndarray) -> list[tuple[float, int, int]]:
        """Prim's algorithm on a dense matrix: n-1 edges (weight, a, b)."""
        n = len(dist)
        in_tree = np.zeros(n, dtype=bool)
        best = np.full(n, np.inf)
        parent = np.full(n, -1)
        best[0] = 0.0
        edges = []
        for _ in range(n):
            cand = np.where(in_tree, np.inf, best)
            v = int(np.argmin(cand))
            in_tree[v] = True
            if parent[v] >= 0:
                edges.append((float(best[v]), int(parent[v]), v))
            closer = (~in_tree) & (dist[v] < best)
            best[closer] = dist[v][closer]
            parent[closer] = v
        return edges

    def _split(self, members: list[int], edges: list[tuple[float, int, int]]) -> list[list[int]]:
        if len(members) <= self.max_group_size:
            return [sorted(members)]
        inside = [e for e in edges if e[1] in members and e[2] in members]
        # Cut the weakest link (largest distance); ties broken by index for repeatability.
        cut = max(inside, key=lambda e: (e[0], -e[1], -e[2]))
        keep = [e for e in inside if e is not cut]
        # Find the two components left after the cut.
        adj = {m: [] for m in members}
        for _, a, b in keep:
            adj[a].append(b)
            adj[b].append(a)
        side, stack = {cut[1]}, [cut[1]]
        while stack:
            for nb in adj[stack.pop()]:
                if nb not in side:
                    side.add(nb)
                    stack.append(nb)
        left = [m for m in members if m in side]
        right = [m for m in members if m not in side]
        return self._split(left, keep) + self._split(right, keep)

    def build(self) -> list[list[int]]:
        """Groups of feature indices, each of size <= max_group_size, covering every feature once."""
        dist = self.correlation_distance()
        groups = self._split(list(range(self.n)), self._mst_edges(dist))
        return sorted(groups, key=lambda g: g[0])
