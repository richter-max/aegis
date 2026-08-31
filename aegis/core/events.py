"""Canonical event schema for AEGIS traces.

Every trace record is written with a ``kind`` field by :class:`aegis.core.trace.TraceWriter`
and read back through :func:`event_type` here. Both sides import from this module so the
writer and the readers cannot drift apart.

That drift is not hypothetical: an earlier version of this code wrote ``kind`` while the
evaluation layer looked for ``type``/``event``. Every metric silently evaluated to zero and
the benchmark reported 0% attack success for months. See ``tests/test_events.py``.
"""

from __future__ import annotations

from typing import Any, Final

#: The field name used to store the event type in ``trace.jsonl``.
EVENT_TYPE_FIELD: Final[str] = "kind"

#: Field names accepted when reading, for backwards compatibility with older traces.
_LEGACY_TYPE_FIELDS: Final[tuple[str, ...]] = ("type", "event")

# --- Event kinds -----------------------------------------------------------
# Anything the evaluation layer keys on lives here as a constant, so a rename
# is a single edit and mypy catches the rest.

RUN_START: Final[str] = "run_start"
RUN_END: Final[str] = "run_end"
SCENARIO_LOADED: Final[str] = "scenario_loaded"
SCENARIO_TEXT: Final[str] = "scenario_text"
BENCH_CONFIG: Final[str] = "bench_config"

AGENT_START: Final[str] = "agent_start"
AGENT_END: Final[str] = "agent_end"

USER_MESSAGE: Final[str] = "user_message"
ASSEMBLED_INSTRUCTION: Final[str] = "assembled_instruction"
UNTRUSTED_CONTENT_RECEIVED: Final[str] = "untrusted_content_received"

DECODE_ATTEMPT: Final[str] = "decode_attempt"
DECODE_SUCCESS: Final[str] = "decode_success"
DECODE_FAILED: Final[str] = "decode_failed"

TOOL_DECISION: Final[str] = "tool_decision"
TOOL_BLOCKED: Final[str] = "tool_blocked"
TOOL_RESULT: Final[str] = "tool_result"


def event_type(event: dict[str, Any]) -> str:
    """Return the event kind, or an empty string if the record has none.

    Reads the canonical field first, then the legacy names so traces recorded by
    older versions still evaluate correctly.
    """
    value = event.get(EVENT_TYPE_FIELD)
    if isinstance(value, str):
        return value

    for field in _LEGACY_TYPE_FIELDS:
        value = event.get(field)
        if isinstance(value, str):
            return value

    return ""
