"""Detector: packet in, anomaly score out (owner: Harsh).

Glues the feature extractor (Krishkumar) to KitNET, with every setting read from
configs/default.yaml.

    det = Detector.from_config()
    for pkt in PcapSource("capture.pcap"):
        score = det.process(pkt)     # 0.0 until training is finished
"""

from __future__ import annotations

from dataclasses import dataclass

from nids.capture import Packet
from nids.config import extractor_kwargs, load_config
from nids.features import FeatureExtractor
from nids.model.kitnet import KitNET


@dataclass
class Result:
    packet: Packet
    score: float
    trained: bool       # False while the model was still learning from this packet


class Detector:
    def __init__(self, extractor: FeatureExtractor, model: KitNET):
        self.extractor = extractor
        self.model = model

    @classmethod
    def from_config(cls, config_path=None, **model_overrides) -> Detector:
        cfg = load_config(config_path)
        fe = FeatureExtractor(**extractor_kwargs(cfg))
        m = {**cfg["model"], **{k: v for k, v in model_overrides.items() if v is not None}}
        model = KitNET(fe.n_features, max_group_size=m["max_group_size"], fm_grace=m["fm_grace"],
                       ad_grace=m["ad_grace"], hidden_ratio=m["hidden_ratio"],
                       learning_rate=m["learning_rate"], seed=m.get("seed", 0))
        return cls(fe, model)

    def process(self, pkt: Packet) -> Result:
        x = self.extractor.process(pkt)
        trained = self.model.is_trained
        return Result(pkt, self.model.process(x), trained)
