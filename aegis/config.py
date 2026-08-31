from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegis.scenarios import corpus

GUARDS: list[str] = ["none", "keywords", "semantic", "layered"]
POLICIES: list[str] = ["strict", "permissive"]


@dataclass(frozen=True)
class BenchConfig:
    scenarios: list[str]
    policies: list[str]
    guards: list[str]
    out: str = "runs"
    report_root: str = "reports/bench"
    report_id: str | None = None


def _resolve_scenarios(raw: Any) -> list[str]:
    """Accept an explicit list, the string ``"all"``, or a filter object."""
    if raw is None or raw == "all":
        return corpus.all_names()

    if isinstance(raw, list):
        unknown = [n for n in raw if n not in corpus.BY_NAME]
        if unknown:
            raise ValueError(f"Unknown scenarios in config: {', '.join(unknown)}")
        return list(raw)

    if isinstance(raw, dict):
        return corpus.select(
            families_filter=raw.get("families"),
            tiers=raw.get("tiers"),
            include_benign=bool(raw.get("include_benign", True)),
        )

    raise ValueError(f"Cannot interpret 'scenarios': {raw!r}")


def load_bench_config(path: str | Path) -> BenchConfig:
    data: dict[str, Any] = json.loads(Path(path).read_text(encoding="utf-8"))

    scenarios = _resolve_scenarios(data.get("scenarios"))
    if not scenarios:
        raise ValueError("Config selected zero scenarios")

    policies = list(data.get("policies") or POLICIES)
    for p in policies:
        if p not in POLICIES:
            raise ValueError(f"Unknown policy {p!r}. Known: {', '.join(POLICIES)}")

    # Accept "guards": [...] and the older singular "guard": "..."
    raw_guards = data.get("guards")
    if raw_guards is None and data.get("guard") is not None:
        raw_guards = [data["guard"]]
    guards = list(raw_guards or GUARDS)
    for g in guards:
        if g not in GUARDS:
            raise ValueError(f"Unknown guard {g!r}. Known: {', '.join(GUARDS)}")

    return BenchConfig(
        scenarios=scenarios,
        policies=policies,
        guards=guards,
        out=str(data.get("out", "runs")),
        report_root=str(data.get("report_root", "reports/bench")),
        report_id=data.get("report_id"),
    )
