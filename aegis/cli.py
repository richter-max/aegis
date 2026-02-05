from __future__ import annotations

import argparse
from pathlib import Path

from rich import print

from aegis.core.run import new_run
from aegis.tools.send_email import SendEmailTool
from aegis.defenses.approval_monitor import ApprovalMonitor, Policy


def main() -> None:
    parser = argparse.ArgumentParser(prog="aegis")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="Run a scenario in the harness")
    run.add_argument("--scenario", required=True, help="Scenario file name (without extension)")
    run.add_argument("--out", default="runs", help="Output folder for run artifacts")
    run.add_argument("--demo-email", action="store_true", help="Demo: attempt a send_email tool call")

    args = parser.parse_args()

    if args.cmd == "run":
        scenario_path = Path("aegis/scenarios") / f"{args.scenario}.txt"
        if not scenario_path.exists():
            raise SystemExit(f"Scenario not found: {scenario_path}")

        ctx = new_run(args.out)
        scenario_text = scenario_path.read_text(encoding="utf-8")

        ctx.trace.event("scenario_loaded", name=args.scenario, path=str(scenario_path))
        ctx.trace.event("scenario_text", text=scenario_text)

        print("[bold green]AEGIS[/bold green] ✅")
        print(f"Run ID:   [cyan]{ctx.run_id}[/cyan]")
        print(f"Run dir:  [cyan]{ctx.run_dir.resolve()}[/cyan]")
        print(f"Scenario: [cyan]{args.scenario}[/cyan]\n")
        print(scenario_text)

        # Minimal demo flow (no LLM yet)
        ctx.trace.event("agent_start", mode="demo_no_llm")

        if args.demo_email:
            tool = SendEmailTool()
            monitor = ApprovalMonitor(policy=Policy.default())

            proposed = tool.propose(
                to="test@example.com",
                subject="AEGIS demo",
                body="If you see this, the tool ran (mocked).",
            )

            decision = monitor.decide(proposed_call=proposed)

            ctx.trace.event(
                "tool_decision",
                tool_name=proposed.name,
                allowed=decision.allowed,
                reason=decision.reason,
                args=proposed.args,
            )

            if decision.allowed:
                result = tool.execute(ctx=ctx, **proposed.args)
                ctx.trace.event("tool_result", tool_name=proposed.name, result=result)
            else:
                ctx.trace.event("tool_blocked", tool_name=proposed.name)

        ctx.trace.event("agent_end")
        ctx.trace.event("run_end", run_id=ctx.run_id)


if __name__ == "__main__":
    main()
