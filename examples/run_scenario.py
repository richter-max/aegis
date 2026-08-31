#!/usr/bin/env python3
"""Programmatic use of the AEGIS harness.

Runs the same scenario under three defense configurations and prints the outcome of
each, which is the shortest demonstration of what the harness measures.

    python examples/run_scenario.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from aegis.core import events as ev
from aegis.core.run import new_run
from aegis.core.runner import run_scenario
from aegis.eval.metrics import evaluate_run


def evaluate(scenario: str, policy: str, guard: str, out_root: str) -> dict:
    ctx = new_run(out_root)
    run_scenario(ctx=ctx, scenario_name=scenario, policy_name=policy, guard=guard)
    ctx.trace.event(ev.RUN_END, run_id=ctx.run_id)
    return evaluate_run(Path(ctx.run_dir))["metrics"]


def main() -> None:
    configurations = [
        ("permissive", "none"),
        ("permissive", "layered"),
        ("strict", "none"),
    ]

    with tempfile.TemporaryDirectory() as tmp:
        for scenario in ("indirect_injection_01", "indirect_injection_04"):
            print(f"\n{scenario}")
            print("-" * 68)
            for policy, guard in configurations:
                m = evaluate(scenario, policy, guard, tmp)
                layer = m["blocking_layer"] or "—"
                print(f"  policy={policy:<11} guard={guard:<9} "
                      f"blocked_at={layer:<9} {m['judge_reason']}")

    print(
        "\nBoth scenarios carry the same intent. The first names the attacker address\n"
        "outright; the second uses a compliance pretext and a plausible vendor domain.\n"
        "Only the first is stopped by content inspection."
    )


if __name__ == "__main__":
    main()
