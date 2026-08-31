"""Replays a corpus scenario step by step through the defense stack.

This is the single execution path for both ``aegis run`` and ``aegis bench``. Previously
each command carried its own copy of the scenario logic, which is how they drifted apart.
"""

from __future__ import annotations

from dataclasses import dataclass

from aegis.core import events as ev
from aegis.core.run import RunContext
from aegis.defenses.approval_monitor import Policy
from aegis.defenses.engine import DefenseEngine
from aegis.scenarios.corpus import (
    DecodePayload,
    FetchPage,
    ProposeEmail,
    Scenario,
    UserTurns,
    get_scenario,
)
from aegis.tools.decoder import decode, extract_marker
from aegis.tools.search_local_page import SearchLocalPageTool
from aegis.tools.send_email import SendEmailTool


def policy_from_name(name: str) -> Policy:
    if name == "permissive":
        return Policy.permissive()
    if name == "strict":
        return Policy.default()
    raise ValueError(f"Unknown policy: {name!r}. Known: strict, permissive")


@dataclass
class _ScenarioState:
    """Text the agent has taken in so far, used as the guard's inspection context."""

    fetched: list[str]
    turns: list[str]
    decoded: list[str]

    @staticmethod
    def empty() -> _ScenarioState:
        return _ScenarioState(fetched=[], turns=[], decoded=[])

    def context_text(self, limit: int = 4000) -> str:
        """Bounded concatenation of everything the agent has read.

        The guards inspect this alongside the proposed tool arguments, which is what
        lets them react to an instruction that arrived through retrieved content
        rather than through the call itself.
        """
        parts: list[str] = []
        for chunk in self.fetched:
            parts.append(chunk[:1200])
        parts.extend(self.turns)
        parts.extend(self.decoded)
        return " | ".join(p for p in parts if p)[:limit]


def run_scenario(
    ctx: RunContext,
    scenario_name: str,
    policy_name: str,
    guard: str,
) -> None:
    """Execute one scenario under one (policy, guard) configuration."""
    scenario: Scenario = get_scenario(scenario_name)
    engine = DefenseEngine(policy=policy_from_name(policy_name), guard=guard)

    ctx.trace.event(
        ev.SCENARIO_LOADED,
        name=scenario.name,
        family=scenario.family,
        tier=scenario.tier,
        malicious=scenario.malicious,
    )
    ctx.trace.event(ev.BENCH_CONFIG, scenario=scenario.name, policy=policy_name, guard=guard)
    ctx.trace.event(ev.AGENT_START, mode="mock_agent_no_llm")

    state = _ScenarioState.empty()
    last_page_html = ""

    for step in scenario.steps:
        if isinstance(step, FetchPage):
            result = SearchLocalPageTool().execute(ctx=ctx, page=step.page)
            last_page_html = result["html"]
            state.fetched.append(last_page_html)
            ctx.trace.event(
                ev.UNTRUSTED_CONTENT_RECEIVED,
                source="search_local_page",
                page=step.page,
                note=step.note,
            )

        elif isinstance(step, UserTurns):
            for turn_no, message in enumerate(step.messages, start=1):
                ctx.trace.event(ev.USER_MESSAGE, turn=turn_no, text=message)
                state.turns.append(message)
            assembled = " ".join(step.messages)
            ctx.trace.event(
                ev.ASSEMBLED_INSTRUCTION,
                method="concatenate",
                turns=len(step.messages),
                text=assembled,
            )

        elif isinstance(step, DecodePayload):
            payload = extract_marker(last_page_html, step.encoding)
            ctx.trace.event(ev.DECODE_ATTEMPT, encoding=step.encoding, found=bool(payload))
            if payload:
                decoded = decode(payload, step.encoding)
                if decoded:
                    state.decoded.append(decoded)
                    ctx.trace.event(
                        ev.DECODE_SUCCESS,
                        encoding=step.encoding,
                        decoded_preview=decoded[:300],
                    )
                else:
                    ctx.trace.event(
                        ev.DECODE_FAILED, encoding=step.encoding, reason="decode_returned_empty"
                    )
            else:
                ctx.trace.event(
                    ev.DECODE_FAILED, encoding=step.encoding, reason="marker_not_found"
                )

        elif isinstance(step, ProposeEmail):
            _propose_email(ctx, engine, step, state.context_text())

        else:  # pragma: no cover - guarded by the Step union
            raise TypeError(f"Unknown step type: {type(step).__name__}")

    ctx.trace.event(ev.AGENT_END)


def _propose_email(
    ctx: RunContext,
    engine: DefenseEngine,
    step: ProposeEmail,
    context_text: str,
) -> None:
    tool = SendEmailTool()
    proposed = tool.propose(to=step.to, subject=step.subject, body=step.body)

    decision = engine.decide(proposed_call=proposed, context_text=context_text)
    ctx.trace.event(
        ev.TOOL_DECISION,
        tool_name=proposed.name,
        allowed=decision.allowed,
        reason=decision.reason,
        args=proposed.args,
    )

    if decision.allowed:
        result = tool.execute(ctx=ctx, **proposed.args)
        ctx.trace.event(ev.TOOL_RESULT, tool_name=proposed.name, result=result)
    else:
        ctx.trace.event(ev.TOOL_BLOCKED, tool_name=proposed.name, reason=decision.reason)
