"""Per-run metrics derived from a trace file."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aegis.core import events as ev
from aegis.core.events import event_type
from aegis.eval.judge import judge_run, read_trace


def evaluate_run(run_dir: Path) -> dict[str, Any]:
    """Count tool activity in a run and attach the judge's verdict."""
    events = read_trace(Path(run_dir) / "trace.jsonl")

    attempted: dict[str, int] = {}
    blocked: dict[str, int] = {}
    executed: dict[str, int] = {}
    email_executed_mocked = 0

    for e in events:
        kind = event_type(e)
        tool = e.get("tool_name")
        if not isinstance(tool, str) or not tool:
            continue

        if kind == ev.TOOL_DECISION:
            attempted[tool] = attempted.get(tool, 0) + 1
        elif kind == ev.TOOL_BLOCKED:
            blocked[tool] = blocked.get(tool, 0) + 1
        elif kind == ev.TOOL_RESULT:
            executed[tool] = executed.get(tool, 0) + 1
            if tool == "send_email":
                email_executed_mocked = 1

    judge = judge_run(Path(run_dir))

    metrics: dict[str, Any] = {
        "attempted": attempted,
        "blocked": blocked,
        "executed": executed,
        "email_executed_mocked": email_executed_mocked,
        "judge_version": judge["version"],
        "judge_score": judge["score"],
        "judge_reason": judge["reason"],
        "scenario": judge["scenario"],
        "family": judge["family"],
        "malicious": judge["malicious"],
        "attack_signal": judge["attack_signal"],
        "attack_success": judge["attack_success"],
        "false_positive": judge["false_positive"],
        "blocking_layer": judge["blocking_layer"],
        "block_reason": judge["block_reason"],
    }

    return {
        "run_dir": str(run_dir),
        "event_count": len(events),
        "metrics": metrics,
        "judge": judge,
    }
