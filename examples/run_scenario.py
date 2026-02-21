#!/usr/bin/env python3
"""
run_scenario.py — AEGIS Quick Start Example

Demonstrates how to programmatically run a security scenario and read the results.
This is the equivalent of running:

    aegis run --scenario tool_exfiltration --policy strict
    aegis eval --latest

Usage:
    python examples/run_scenario.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def run_aegis(scenario: str, policy: str) -> dict:
    """Run an AEGIS scenario and return the JSON eval result."""
    # Run the scenario
    result = subprocess.run(
        [sys.executable, "-m", "aegis.cli", "run", "--scenario", scenario, "--policy", policy],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"[ERROR] aegis run failed:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)

    # Evaluate the latest run
    eval_result = subprocess.run(
        [sys.executable, "-m", "aegis.cli", "eval", "--latest"],
        capture_output=True,
        text=True,
    )
    if eval_result.returncode != 0:
        print(f"[ERROR] aegis eval failed:\n{eval_result.stderr}", file=sys.stderr)
        sys.exit(1)

    # Read the metrics from the most recent run
    runs_dir = Path("runs")
    if not runs_dir.exists():
        print("[ERROR] No runs/ directory found. Did the scenario execute?", file=sys.stderr)
        sys.exit(1)

    latest_run = sorted(runs_dir.iterdir())[-1]
    metrics_path = latest_run / "metrics.json"
    if not metrics_path.exists():
        print(f"[ERROR] No metrics.json in {latest_run}", file=sys.stderr)
        sys.exit(1)

    return json.loads(metrics_path.read_text(encoding="utf-8"))


def main() -> None:
    scenario = "tool_exfiltration"
    policy = "strict"

    print(f"\nRunning AEGIS scenario: {scenario!r} with policy: {policy!r}\n")
    metrics = run_aegis(scenario, policy)

    judge = metrics.get("judge", {})
    score = judge.get("score", 0.0)
    attack_success = metrics["metrics"].get("attack_success", False)
    verdict = "FAILED — attack succeeded" if attack_success else "mitigated"

    # Emit the deterministic result in JSON
    result = {
        "scenario": scenario,
        "policy": policy,
        "score": round(score, 2),
        "verdict": verdict,
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
