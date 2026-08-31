from __future__ import annotations

import argparse
import json
from pathlib import Path

from rich import print

from aegis.bench import bench
from aegis.config import GUARDS, POLICIES, load_bench_config
from aegis.core import events as ev
from aegis.core.run import new_run
from aegis.core.runner import run_scenario
from aegis.eval.metrics import evaluate_run
from aegis.scenarios import corpus


def _latest_run_dir(out_root: str) -> Path | None:
    root = Path(out_root)
    if not root.exists():
        return None
    dirs = [p for p in root.iterdir() if p.is_dir()]
    return sorted(dirs)[-1] if dirs else None


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis", description="Agent security evaluation harness")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="Run a single scenario")
    run.add_argument("--scenario", required=True, help="Scenario name (see 'aegis scenarios')")
    run.add_argument("--policy", choices=POLICIES, default="strict")
    run.add_argument("--guard", choices=GUARDS, default="none")
    run.add_argument("--out", default="runs", help="Output root for run artifacts")

    ev_p = sub.add_parser("eval", help="Evaluate a run directory")
    ev_p.add_argument("--run", help="Run id folder name")
    ev_p.add_argument("--latest", action="store_true", help="Evaluate the most recent run")
    ev_p.add_argument("--out", default="runs")

    b = sub.add_parser("bench", help="Sweep scenarios across policies and guards")
    b.add_argument("--config", help="Path to a bench config JSON")
    b.add_argument("--scenarios", nargs="+", help="Scenario names (default: whole corpus)")
    b.add_argument("--policies", nargs="+", choices=POLICIES, default=POLICIES)
    b.add_argument("--guards", nargs="+", choices=GUARDS, default=GUARDS)
    b.add_argument("--out", default="runs")
    b.add_argument("--report-root", default="reports/bench")
    b.add_argument("--report-id")

    sc = sub.add_parser("scenarios", help="List the scenario corpus")
    sc.add_argument("--family", help="Filter by family")
    sc.add_argument("--tier", help="Filter by evasion tier")

    return parser


def _cmd_scenarios(args: argparse.Namespace) -> None:
    rows = [
        s
        for s in corpus.CORPUS
        if (not args.family or s.family == args.family) and (not args.tier or s.tier == args.tier)
    ]
    print(f"[bold]{len(rows)} scenarios[/bold]\n")
    current = ""
    for s in rows:
        if s.family != current:
            current = s.family
            print(f"[bold cyan]{current}[/bold cyan]")
        label = "benign" if not s.malicious else s.tier
        print(f"  [green]{s.name:<32}[/green] [dim]{label:<10}[/dim] {s.description}")


def _cmd_run(args: argparse.Namespace) -> None:
    ctx = new_run(args.out)
    run_scenario(ctx=ctx, scenario_name=args.scenario, policy_name=args.policy, guard=args.guard)
    ctx.trace.event(ev.RUN_END, run_id=ctx.run_id)

    m = evaluate_run(Path(ctx.run_dir))["metrics"]
    print("[bold green]AEGIS RUN[/bold green]")
    print(f"Scenario: [cyan]{args.scenario}[/cyan] ({m['family']}, malicious={m['malicious']})")
    print(f"Policy:   [cyan]{args.policy}[/cyan]   Guards: [cyan]{args.guard}[/cyan]")
    print(f"Trace:    [cyan]{Path(ctx.run_dir).resolve() / 'trace.jsonl'}[/cyan]")
    print(f"Outcome:  [bold]{m['judge_reason']}[/bold]")
    if m["block_reason"]:
        print(f"Blocked by [cyan]{m['blocking_layer']}[/cyan]: {m['block_reason']}")


def _cmd_eval(args: argparse.Namespace) -> None:
    if args.latest:
        run_dir = _latest_run_dir(args.out)
        if run_dir is None:
            raise SystemExit(f"No runs found in {args.out}")
    else:
        if not args.run:
            raise SystemExit("Provide --run <RUN_ID> or --latest")
        run_dir = Path(args.out) / args.run

    result = evaluate_run(run_dir)
    (run_dir / "metrics.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

    m = result["metrics"]
    print("[bold green]AEGIS EVAL[/bold green]")
    print(f"Run dir:  [cyan]{run_dir.resolve()}[/cyan]")
    print(f"Events:   [cyan]{result['event_count']}[/cyan]")
    print(f"Scenario: [cyan]{m['scenario']}[/cyan]")
    print(f"Outcome:  [bold]{m['judge_reason']}[/bold]")


def _cmd_bench(args: argparse.Namespace) -> None:
    if args.config:
        cfg = load_bench_config(args.config)
        scenarios: list[str] = cfg.scenarios
        policies, guards = cfg.policies, cfg.guards
        out_root, report_root = cfg.out, cfg.report_root
        # Command line flags override the config file.
        report_id = args.report_id or cfg.report_id
        print(f"[bold]Config:[/bold] [cyan]{Path(args.config).resolve()}[/cyan]")
    else:
        scenarios = args.scenarios or corpus.all_names()
        policies, guards = args.policies, args.guards
        out_root, report_root, report_id = args.out, args.report_root, args.report_id

    res = bench(
        scenarios=scenarios,
        policies=policies,
        guards=guards,
        out_root=out_root,
        report_root=report_root,
        report_id=report_id,
    )
    payload = res["payload"]
    counts = payload["counts"]

    print("[bold green]AEGIS BENCH[/bold green]")
    print(
        f"{counts['scenarios']} scenarios "
        f"({counts['malicious']} malicious, {counts['benign']} benign), "
        f"{counts['runs']} runs\n"
    )
    print(f"{'policy':<12}{'guards':<12}{'attack success':>16}{'false positives':>18}")
    for row in payload["aggregate"]:
        asr = row["attack_success_rate"]
        fpr = row["false_positive_rate"]
        asr_s = "—" if asr is None else f"{asr * 100:.1f}%"
        fpr_s = "—" if fpr is None else f"{fpr * 100:.1f}%"
        print(f"{row['policy']:<12}{row['guard']:<12}{asr_s:>16}{fpr_s:>18}")

    print(f"\nSummary: [cyan]{Path(res['summary_md']).resolve()}[/cyan]")


def main() -> None:
    args = _build_parser().parse_args()
    if args.cmd == "scenarios":
        _cmd_scenarios(args)
    elif args.cmd == "run":
        _cmd_run(args)
    elif args.cmd == "eval":
        _cmd_eval(args)
    elif args.cmd == "bench":
        _cmd_bench(args)
    else:  # pragma: no cover
        raise SystemExit(f"Unknown command: {args.cmd}")


if __name__ == "__main__":
    main()
