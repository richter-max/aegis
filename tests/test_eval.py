"""Tests for the evaluation layer.

This module had zero coverage while carrying the bug that zeroed every metric, so the
tests here deliberately assert on concrete numbers rather than on "it ran".
"""

from __future__ import annotations

from pathlib import Path

from aegis.bench import aggregate, aggregate_by_tier, bench
from aegis.core import events as ev
from aegis.core.run import new_run
from aegis.core.runner import run_scenario
from aegis.eval.judge import judge_run
from aegis.eval.metrics import evaluate_run


def _run(tmp_path: Path, scenario: str, policy: str, guard: str) -> Path:
    ctx = new_run(str(tmp_path))
    run_scenario(ctx=ctx, scenario_name=scenario, policy_name=policy, guard=guard)
    ctx.trace.event(ev.RUN_END, run_id=ctx.run_id)
    return Path(ctx.run_dir)


class TestJudgeOutcomes:
    def test_obvious_attack_succeeds_without_defenses(self, tmp_path: Path) -> None:
        result = judge_run(_run(tmp_path, "indirect_injection_01", "permissive", "none"))
        assert result["malicious"] is True
        assert result["tool_executed"] is True
        assert result["attack_success"] is True

    def test_policy_blocks_the_same_attack(self, tmp_path: Path) -> None:
        result = judge_run(_run(tmp_path, "indirect_injection_01", "strict", "none"))
        assert result["attack_success"] is False
        assert result["blocking_layer"] == "policy"

    def test_keyword_guard_blocks_obvious_attack(self, tmp_path: Path) -> None:
        result = judge_run(_run(tmp_path, "indirect_injection_01", "permissive", "keywords"))
        assert result["attack_success"] is False
        assert result["blocking_layer"] == "keyword"

    def test_evasive_attack_survives_content_inspection(self, tmp_path: Path) -> None:
        """The corpus must contain attacks the guards miss, or the benchmark says nothing."""
        result = judge_run(_run(tmp_path, "indirect_injection_04", "permissive", "layered"))
        assert result["malicious"] is True
        assert result["attack_success"] is True

    def test_benign_scenario_is_not_counted_as_attack(self, tmp_path: Path) -> None:
        result = judge_run(_run(tmp_path, "benign_01_status_update", "permissive", "none"))
        assert result["malicious"] is False
        assert result["attack_success"] is False
        assert result["false_positive"] is False

    def test_blocked_benign_scenario_is_a_false_positive(self, tmp_path: Path) -> None:
        result = judge_run(_run(tmp_path, "benign_01_status_update", "strict", "none"))
        assert result["false_positive"] is True

    def test_keyword_guard_false_positive_on_password_policy(self, tmp_path: Path) -> None:
        """A legitimate mail about passwords is blocked by literal matching."""
        result = judge_run(_run(tmp_path, "benign_04_password_policy", "permissive", "keywords"))
        assert result["false_positive"] is True
        assert result["blocking_layer"] == "keyword"

    def test_attack_signal_detected_for_each_family(self, tmp_path: Path) -> None:
        for scenario in (
            "indirect_injection_01",
            "context_fragmentation_01",
            "token_smuggling_01",
        ):
            result = judge_run(_run(tmp_path, scenario, "permissive", "none"))
            assert result["attack_signal"] is True, scenario

    def test_missing_trace_does_not_crash(self, tmp_path: Path) -> None:
        result = judge_run(tmp_path / "does_not_exist")
        assert result["scenario"] == "unknown"
        assert result["attack_success"] is False


class TestMetrics:
    def test_counts_reflect_a_blocked_call(self, tmp_path: Path) -> None:
        metrics = evaluate_run(_run(tmp_path, "indirect_injection_01", "strict", "none"))["metrics"]
        assert metrics["attempted"]["send_email"] == 1
        assert metrics["blocked"]["send_email"] == 1
        assert metrics["executed"] == {}
        assert metrics["email_executed_mocked"] == 0

    def test_counts_reflect_an_executed_call(self, tmp_path: Path) -> None:
        metrics = evaluate_run(_run(tmp_path, "indirect_injection_01", "permissive", "none"))[
            "metrics"
        ]
        assert metrics["executed"]["send_email"] == 1
        assert metrics["email_executed_mocked"] == 1

    def test_event_count_is_nonzero(self, tmp_path: Path) -> None:
        """Guards against the whole trace being unreadable, as it once was."""
        result = evaluate_run(_run(tmp_path, "token_smuggling_01", "permissive", "layered"))
        assert result["event_count"] > 5


class TestAggregation:
    def _rows(self) -> list[dict]:
        return [
            {"policy": "permissive", "guard": "none", "malicious": True, "tier": "obvious",
             "attack_success": True, "false_positive": False},
            {"policy": "permissive", "guard": "none", "malicious": True, "tier": "evasive",
             "attack_success": True, "false_positive": False},
            {"policy": "permissive", "guard": "none", "malicious": False, "tier": "benign",
             "attack_success": False, "false_positive": False},
            {"policy": "permissive", "guard": "keywords", "malicious": True, "tier": "obvious",
             "attack_success": False, "false_positive": False},
            {"policy": "permissive", "guard": "keywords", "malicious": True, "tier": "evasive",
             "attack_success": True, "false_positive": False},
            {"policy": "permissive", "guard": "keywords", "malicious": False, "tier": "benign",
             "attack_success": False, "false_positive": True},
        ]

    def test_rates_are_computed_over_the_right_denominators(self) -> None:
        rows = {(r["policy"], r["guard"]): r for r in aggregate(self._rows())}

        none = rows[("permissive", "none")]
        assert none["attack_success_rate"] == 1.0
        assert none["false_positive_rate"] == 0.0

        keywords = rows[("permissive", "keywords")]
        assert keywords["attack_success_rate"] == 0.5
        assert keywords["false_positive_rate"] == 1.0

    def test_benign_scenarios_excluded_from_attack_rate(self) -> None:
        row = aggregate(self._rows())[0]
        assert row["malicious_total"] == 2
        assert row["benign_total"] == 1

    def test_tier_breakdown_ignores_benign(self) -> None:
        tiers = {r["tier"] for r in aggregate_by_tier(self._rows())}
        assert "benign" not in tiers

    def test_empty_input_produces_no_rows(self) -> None:
        assert aggregate([]) == []
        assert aggregate_by_tier([]) == []


class TestBenchEndToEnd:
    def test_sweep_produces_consistent_totals(self, tmp_path: Path) -> None:
        scenarios = ["indirect_injection_01", "indirect_injection_04", "benign_01_status_update"]
        result = bench(
            scenarios=scenarios,
            policies=["permissive"],
            guards=["none", "layered"],
            out_root="runs",
            report_root=str(tmp_path / "reports"),
            report_id="test",
        )
        payload = result["payload"]

        assert payload["counts"]["runs"] == len(scenarios) * 2
        assert payload["counts"]["malicious"] == 2
        assert payload["counts"]["benign"] == 1
        assert len(payload["aggregate"]) == 2

        for path_key in ("summary_json", "summary_md", "snippet_md"):
            assert Path(result[path_key]).is_file()

    def test_every_run_gets_its_own_trace(self, tmp_path: Path) -> None:
        result = bench(
            scenarios=["indirect_injection_01", "indirect_injection_02"],
            policies=["strict", "permissive"],
            guards=["none"],
            out_root="runs",
            report_root=str(tmp_path / "reports"),
            report_id="test",
        )
        run_dirs = {r["run_dir"] for r in result["payload"]["results"]}
        assert len(run_dirs) == 4

    def test_defenses_are_not_all_equivalent(self, tmp_path: Path) -> None:
        """If every configuration scored the same the benchmark would be uninformative."""
        result = bench(
            scenarios=["indirect_injection_01", "indirect_injection_04"],
            policies=["permissive"],
            guards=["none", "keywords"],
            out_root="runs",
            report_root=str(tmp_path / "reports"),
            report_id="test",
        )
        rates = {r["guard"]: r["attack_success_rate"] for r in result["payload"]["aggregate"]}
        assert rates["none"] > rates["keywords"]
