"""Tests for the attack scenario runner (owner: Bhavya).

CI never sends attack traffic; it checks that scenarios parse, that bad ones are
rejected, and that a dry run lists the right commands without running them.
"""

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lab"))
from run_scenario import ScenarioError, load_scenario, plan, run  # noqa: E402


def write(tmp_path, data):
    p = tmp_path / "s.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


def test_loads_valid_scenario(tmp_path):
    p = write(tmp_path, {"name": "t", "steps": [
        {"gap": 90},
        {"attack": "portscan", "args": ["--target", "10.10.0.10"]},
    ]})
    sc = load_scenario(p)
    assert sc["name"] == "t" and len(sc["steps"]) == 2


def test_shipped_demo_scenario_is_valid():
    demo = Path(__file__).resolve().parent.parent / "lab" / "scenarios" / "demo.yaml"
    sc = load_scenario(demo)
    attacks = [s["attack"] for s in sc["steps"] if "attack" in s]
    assert attacks == ["portscan", "arpspoof"]


def test_rejects_unknown_attack(tmp_path):
    p = write(tmp_path, {"steps": [{"attack": "nuke"}]})
    with pytest.raises(ScenarioError, match="unknown attack"):
        load_scenario(p)


def test_rejects_step_without_gap_or_attack(tmp_path):
    p = write(tmp_path, {"steps": [{"wait": 5}]})
    with pytest.raises(ScenarioError):
        load_scenario(p)


def test_rejects_negative_gap(tmp_path):
    p = write(tmp_path, {"steps": [{"gap": -1}]})
    with pytest.raises(ScenarioError):
        load_scenario(p)


def test_dry_run_lists_commands_without_running(tmp_path, capsys):
    p = write(tmp_path, {"name": "t", "steps": [
        {"gap": 1},
        {"attack": "dosflood", "args": ["--target", "10.10.0.10", "--mode", "syn"]},
    ]})
    sc = load_scenario(p)
    lines = plan(sc)
    assert "gap: wait 1s" in lines[0]
    assert "dosflood.py --target 10.10.0.10 --mode syn" in lines[1]
    # dry run must not sleep or spawn: returns 0 immediately
    assert run(sc, dry_run=True) == 0
