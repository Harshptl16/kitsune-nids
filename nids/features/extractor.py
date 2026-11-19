"""AfterImage-style feature extractor: one packet in, 115 numbers out (owner: Krishkumar).

For each packet we update five kinds of stream, each at every decay rate lambda:

  type    key                                   value        stats                   per lambda
  MI      (src MAC, src IP)                     frame size   w, mean, std            3
  H       src IP                                frame size   w, mean, std            3
  HH      src IP -> dst IP                      frame size   w, mean, std, mag, rad, cov, pcc   7
  HHjit   src IP -> dst IP                      inter-arrival time  w, mean, std     3
  HpHp    (src IP, sport) -> (dst IP, dport)    frame size   w, mean, std, mag, rad, cov, pcc   7
                                                                                   ----
                                                                                   23 x L lambdas

With the default 5 lambdas that is 115 features. The 2D stats (mag, rad, cov,
pcc) relate a stream to its reverse direction (B->A).

What each group is good at:
  MI    a MAC suddenly claiming another IP (ARP spoofing)
  H     one host sending far more, or differently sized, traffic (floods)
  HH    a conversation changing shape
  HHjit timing that becomes machine-regular (scans, floods)
  HpHp  many brand-new, one-packet sockets (port scans)
"""

from __future__ import annotations

import numpy as np

from nids.capture.packet import Packet

from .incstat import DEFAULT_LAMBDAS
from .streams import StreamTable

STATS_1D = ("w", "mean", "std")
STATS_2D = ("w", "mean", "std", "mag", "rad", "cov", "pcc")
LAYOUT = (("MI", STATS_1D), ("H", STATS_1D), ("HH", STATS_2D), ("HHjit", STATS_1D), ("HpHp", STATS_2D))


class FeatureExtractor:
    def __init__(self, lambdas=DEFAULT_LAMBDAS, prune_every: int = 10_000,
                 prune_eps: float = 1e-3, max_streams: int = 500_000):
        self.lams = np.asarray(lambdas, dtype=float)
        self.table = StreamTable(self.lams, prune_every, prune_eps, max_streams)
        self.n_features = sum(len(stats) for _, stats in LAYOUT) * len(self.lams)

    def feature_names(self) -> list[str]:
        names = []
        for group, stats in LAYOUT:
            for lam in self.lams:
                names.extend(f"{group}_L{lam:g}_{s}" for s in stats)
        return names

    @staticmethod
    def _block(stats: np.ndarray) -> np.ndarray:
        """(k stats, L lambdas) -> flat, lambda-major: [L0 stats..., L1 stats..., ...]."""
        return stats.T.ravel()

    def _two_way(self, key, rev_key, x: float, t: float) -> np.ndarray:
        s = self.table.get(key)
        s.update(x, t)
        cov = self.table.get_cov(key, rev_key)
        cov.update(s, t)
        return np.vstack([s.stats_1d(), cov.stats_2d()])

    def process(self, pkt: Packet) -> np.ndarray:
        t, x = pkt.ts, float(pkt.length)
        tbl = self.table

        mi = tbl.get(("MI", pkt.src_mac, pkt.src_ip))
        mi.update(x, t)

        h = tbl.get(("H", pkt.src_ip))
        h.update(x, t)

        hh = self._two_way(("HH", pkt.src_ip, pkt.dst_ip), ("HH", pkt.dst_ip, pkt.src_ip), x, t)

        jit = tbl.get(("HHjit", pkt.src_ip, pkt.dst_ip))
        gap = 0.0 if jit.t_last is None else max(t - jit.t_last, 0.0)
        jit.update(gap, t)

        sock = self._two_way(("HpHp", pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port, pkt.proto),
                             ("HpHp", pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.src_port, pkt.proto), x, t)

        tbl.tick(t)
        return np.concatenate([
            self._block(mi.stats_1d()),
            self._block(h.stats_1d()),
            self._block(hh),
            self._block(jit.stats_1d()),
            self._block(sock),
        ])
