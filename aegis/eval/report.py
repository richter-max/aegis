"""Markdown rendering of benchmark payloads."""

from __future__ import annotations

from datetime import datetime
from typing import Any


def _esc(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def _pct(value: float | None) -> str:
    return "—" if value is None else f"{value * 100:.1f}%"


def _tick(flag: Any) -> str:
    return "yes" if flag else "no"


def _aggregate_table(payload: dict[str, Any]) -> list[str]:
    lines = [
        "| Policy | Guards | Attack success | False positives |",
        "| :--- | :--- | ---: | ---: |",
    ]
    for row in payload.get("aggregate", []):
        lines.append(
            f"| `{_esc(str(row['policy']))}` | `{_esc(str(row['guard']))}` "
            f"| {_pct(row.get('attack_success_rate'))} "
            f"({row.get('attack_success', 0)}/{row.get('malicious_total', 0)}) "
            f"| {_pct(row.get('false_positive_rate'))} "
            f"({row.get('false_positive', 0)}/{row.get('benign_total', 0)}) |"
        )
    return lines


def _tier_table(payload: dict[str, Any]) -> list[str]:
    lines = [
        "| Policy | Guards | Tier | Attack success |",
        "| :--- | :--- | :--- | ---: |",
    ]
    for row in payload.get("by_tier", []):
        lines.append(
            f"| `{_esc(str(row['policy']))}` | `{_esc(str(row['guard']))}` "
            f"| {_esc(str(row['tier']))} "
            f"| {_pct(row.get('rate'))} ({row.get('success', 0)}/{row.get('total', 0)}) |"
        )
    return lines


def bench_summary_to_markdown(payload: dict[str, Any]) -> str:
    counts = payload.get("counts", {})
    lines: list[str] = [
        "# AEGIS Bench Summary",
        "",
        f"- Generated: **{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}**",
        f"- Report: `{payload.get('report_dir', '')}`",
        f"- Scenarios: {counts.get('scenarios', 0)} "
        f"({counts.get('malicious', 0)} malicious, {counts.get('benign', 0)} benign)",
        f"- Policies: {', '.join(f'`{p}`' for p in payload.get('policies', []))}",
        f"- Guards: {', '.join(f'`{g}`' for g in payload.get('guards', []))}",
        f"- Total runs: {counts.get('runs', 0)}",
        "",
        "## Aggregate",
        "",
        "Attack success is measured over malicious scenarios, false positives over",
        "benign ones. Both are needed: a configuration that blocks every call scores",
        "0% attack success and 100% false positives.",
        "",
    ]
    lines += _aggregate_table(payload)
    lines += ["", "## By evasion tier", "", *_tier_table(payload), ""]

    lines += [
        "## Per-run results",
        "",
        "| Scenario | Family | Tier | Policy | Guards | Signal | Executed | Blocked at | Outcome |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in sorted(
        payload.get("results", []),
        key=lambda x: (str(x["policy"]), str(x["guard"]), str(x["scenario"])),
    ):
        lines.append(
            f"| `{_esc(str(r['scenario']))}` | {_esc(str(r['family']))} | {_esc(str(r['tier']))} "
            f"| `{_esc(str(r['policy']))}` | `{_esc(str(r['guard']))}` "
            f"| {_tick(r['attack_signal'])} | {_tick(r['tool_executed'])} "
            f"| {_esc(str(r['blocking_layer'] or '—'))} | {_esc(str(r['judge_reason']))} |"
        )

    lines.append("")
    return "\n".join(lines)


def readme_snippet(payload: dict[str, Any]) -> str:
    counts = payload.get("counts", {})
    lines = [
        "## Latest AEGIS bench results",
        "",
        f"- Report: `{payload.get('report_dir', '')}`",
        f"- {counts.get('scenarios', 0)} scenarios "
        f"({counts.get('malicious', 0)} malicious, {counts.get('benign', 0)} benign), "
        f"{counts.get('runs', 0)} runs",
        "",
    ]
    lines += _aggregate_table(payload)
    lines += ["", "### By evasion tier", "", *_tier_table(payload), ""]
    return "\n".join(lines)
