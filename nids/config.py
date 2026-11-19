"""Load configs/default.yaml, optionally merged with an override file (owner: Krishkumar)."""

from __future__ import annotations

import copy
from pathlib import Path

import yaml

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "configs" / "default.yaml"


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: str | Path | None = None) -> dict:
    with open(DEFAULT_PATH) as fh:
        cfg = yaml.safe_load(fh)
    if path is not None:
        with open(path) as fh:
            cfg = _merge(cfg, yaml.safe_load(fh) or {})
    return cfg


def extractor_kwargs(cfg: dict) -> dict:
    f = cfg["features"]
    return {"lambdas": f["lambdas"], "prune_every": f["prune_every"],
            "prune_eps": f["prune_eps"], "max_streams": f["max_streams"]}
