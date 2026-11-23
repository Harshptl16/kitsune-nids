"""Run a timed sequence of attacks for a recorded test or the demo (owner: Bhavya).

A scenario is a YAML list of steps: benign gaps and attacks, in order. Running it
plays the steps back to back, calling the existing attack scripts, so one command
produces a labelled test set (every attack logs its own ground truth via
attack_base). A --dry-run prints the plan and the exact commands without sending
anything, which is what CI checks.

    python3 lab/run_scenario.py lab/scenarios/demo.yaml --dry-run
    sudo python3 lab/run_scenario.py lab/scenarios/demo.yaml      # on the Kali attacker VM

Example scenario (lab/scenarios/demo.yaml):
    name: demo
    steps:
      - gap: 90                 # seconds of benign traffic only
      - attack: portscan        # -> lab/attacks/portscan.py
        args: ["--target", "10.10.0.10", "--mode", "syn", "--ports", "1-1024"]
      - gap: 60
      - attack: arpspoof
        args: ["--victim", "10.10.0.20", "--gateway", "10.10.0.1", "--duration", "60"]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

import yaml

ATTACKS_DIR = Path(__file__).resolve().parent / "attacks"
KNOWN = {"portscan", "arpspoof", "dosflood"}


class ScenarioError(Exception):
    pass


def load_scenario(path: str | Path) -> dict:
    data = yaml.safe_load(Path(path).read_text())
    if not isinstance(data, dict) or "steps" not in data:
        raise ScenarioError("scenario must be a mapping with a 'steps' list")
    for i, step in enumerate(data["steps"]):
        if "gap" in step:
            if not isinstance(step["gap"], (int, float)) or step["gap"] < 0:
                raise ScenarioError(f"step {i}: gap must be a non-negative number")
        elif "attack" in step:
            if step["attack"] not in KNOWN:
                raise ScenarioError(f"step {i}: unknown attack {step['attack']!r} (known: {sorted(KNOWN)})")
            if "args" in step and not isinstance(step["args"], list):
                raise ScenarioError(f"step {i}: args must be a list")
        else:
            raise ScenarioError(f"step {i}: each step needs 'gap' or 'attack'")
    return data


def plan(scenario: dict) -> list[str]:
    """Human-readable plan, one line per step (used by --dry-run)."""
    lines = []
    for step in scenario["steps"]:
        if "gap" in step:
            lines.append(f"gap: wait {step['gap']}s (benign traffic only)")
        else:
            script = ATTACKS_DIR / f"{step['attack']}.py"
            args = step.get("args", [])
            lines.append(f"attack: {sys.executable} {script} {' '.join(args)}")
    return lines


def run(scenario: dict, dry_run: bool = False) -> int:
    steps = scenario["steps"]
    print(f"scenario '{scenario.get('name', '?')}': {len(steps)} steps")
    for n, step in enumerate(steps, 1):
        if "gap" in step:
            print(f"[{n}/{len(steps)}] gap {step['gap']}s")
            if not dry_run:
                time.sleep(step["gap"])
        else:
            script = ATTACKS_DIR / f"{step['attack']}.py"
            cmd = [sys.executable, str(script), *step.get("args", [])]
            print(f"[{n}/{len(steps)}] {' '.join(cmd)}")
            if not dry_run:
                r = subprocess.run(cmd)
                if r.returncode != 0:
                    print(f"  step failed (exit {r.returncode}); stopping", file=sys.stderr)
                    return r.returncode
    print("scenario complete" + (" (dry run)" if dry_run else ""))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenario", help="YAML scenario file")
    ap.add_argument("--dry-run", action="store_true", help="print the plan without running anything")
    args = ap.parse_args(argv)
    try:
        scenario = load_scenario(args.scenario)
    except ScenarioError as e:
        ap.error(str(e))
    if args.dry_run:
        print("\n".join(plan(scenario)))
    return run(scenario, dry_run=args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
