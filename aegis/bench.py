"""Benchmark sweep: every scenario against every (policy, guard) configuration."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from aegis.core import events as ev
from aegis.core.run import new_run
from aegis.core.runner import run_scenario
from aegis.eval.metrics import evaluate_run
from aegis.eval.report import bench_summary_to_markdown, readme_snippet
from aegis.scenarios.corpus import get_scenario


@dataclass(frozen=True)
class BenchResult:
    scenario: str
    family: str
    tier: str
    malicious: bool
    policy: str
    guard: str
    run_id: str
    run_dir: str
    tool_executed: bool
    tool_blocked: bool
    blocking_layer: str | None
    attack_success: bool
    false_positive: bool
    attack_signal: bool
    judge_score: float
    judge_reason: str


def aggregate(results: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse per-run results into one row per (policy, guard) configuration.

    Attack success rate is computed over malicious scenarios only; false positive
    rate over benign scenarios only. Reporting one without the other hides the
    trade-off: a guard that blocks everything scores a perfect 0% attack success.
    """
    buckets: dict[tuple[str, str], dict[str, Any]] = {}

    for r in results:
        key = (str(r["policy"]), str(r["guard"]))
        b = buckets.setdefault(
            key,
            {
                "policy": key[0],
                "guard": key[1],
                "malicious_total": 0,
                "attack_success": 0,
                "benign_total": 0,
                "false_positive": 0,
            },
        )
        if r["malicious"]:
            b["malicious_total"] += 1
            if r["attack_success"]:
                b["attack_success"] += 1
        else:
            b["benign_total"] += 1
            if r["false_positive"]:
                b["false_positive"] += 1

    rows: list[dict[str, Any]] = []
    for b in buckets.values():
        mt = int(b["malicious_total"])
        bt = int(b["benign_total"])
        b["attack_success_rate"] = (b["attack_success"] / mt) if mt else None
        b["false_positive_rate"] = (b["false_positive"] / bt) if bt else None
        rows.append(b)

    rows.sort(key=lambda r: (str(r["policy"]), str(r["guard"])))
    return rows


def aggregate_by_tier(results: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attack success per evasion tier, for each configuration."""
    buckets: dict[tuple[str, str, str], dict[str, Any]] = {}

    for r in results:
        if not r["malicious"]:
            continue
        key = (str(r["policy"]), str(r["guard"]), str(r["tier"]))
        b = buckets.setdefault(
            key,
            {"policy": key[0], "guard": key[1], "tier": key[2], "total": 0, "success": 0},
        )
        b["total"] += 1
        if r["attack_success"]:
            b["success"] += 1

    rows = list(buckets.values())
    for b in rows:
        b["rate"] = b["success"] / b["total"] if b["total"] else None

    tier_order = {"obvious": 0, "moderate": 1, "evasive": 2}
    rows.sort(key=lambda r: (str(r["policy"]), str(r["guard"]), tier_order.get(str(r["tier"]), 9)))
    return rows


def bench(
    scenarios: Sequence[str],
    policies: Sequence[str],
    guards: Sequence[str],
    out_root: str = "runs",
    report_root: str = "reports/bench",
    report_id: str | None = None,
) -> dict[str, Any]:
    if report_id is None:
        from datetime import datetime

        report_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    report_dir = Path(report_root) / report_id
    runs_dir = report_dir / out_root
    runs_dir.mkdir(parents=True, exist_ok=True)

    results: list[BenchResult] = []

    for scenario_name in scenarios:
        scenario = get_scenario(scenario_name)
        for policy in policies:
            for guard in guards:
                ctx = new_run(str(runs_dir))
                run_scenario(ctx=ctx, scenario_name=scenario_name, policy_name=policy, guard=guard)
                ctx.trace.event(ev.RUN_END, run_id=ctx.run_id)

                m = evaluate_run(Path(ctx.run_dir))["metrics"]

                results.append(
                    BenchResult(
                        scenario=scenario_name,
                        family=scenario.family,
                        tier=scenario.tier,
                        malicious=scenario.malicious,
                        policy=policy,
                        guard=guard,
                        run_id=ctx.run_id,
                        run_dir=str(ctx.run_dir),
                        tool_executed=bool(m["executed"].get("send_email", 0)),
                        tool_blocked=bool(m["blocked"].get("send_email", 0)),
                        blocking_layer=m["blocking_layer"],
                        attack_success=bool(m["attack_success"]),
                        false_positive=bool(m["false_positive"]),
                        attack_signal=bool(m["attack_signal"]),
                        judge_score=float(m["judge_score"]),
                        judge_reason=str(m["judge_reason"]),
                    )
                )

    result_dicts = [asdict(r) for r in results]

    payload: dict[str, Any] = {
        "report_id": report_id,
        "report_dir": report_dir.as_posix(),
        "runs_dir": runs_dir.as_posix(),
        "scenarios": list(scenarios),
        "policies": list(policies),
        "guards": list(guards),
        "counts": {
            "scenarios": len(scenarios),
            "malicious": sum(1 for r in result_dicts if r["malicious"]) // max(
                1, len(policies) * len(guards)
            ),
            "benign": sum(1 for r in result_dicts if not r["malicious"]) // max(
                1, len(policies) * len(guards)
            ),
            "runs": len(result_dicts),
        },
        "results": result_dicts,
        "aggregate": aggregate(result_dicts),
        "by_tier": aggregate_by_tier(result_dicts),
    }

    summary_json = report_dir / "bench_summary.json"
    summary_md = report_dir / "bench_summary.md"
    snippet_md = report_dir / "README_SNIPPET.md"

    summary_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    summary_md.write_text(bench_summary_to_markdown(payload), encoding="utf-8")
    snippet_md.write_text(readme_snippet(payload), encoding="utf-8")

    return {
        "summary_json": str(summary_json),
        "summary_md": str(summary_md),
        "snippet_md": str(snippet_md),
        "payload": payload,
    }
