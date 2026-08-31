"""Regression tests for the two bugs that silently zeroed the benchmark.

Bug 1: ``TraceWriter`` wrote the event type under ``kind`` while the evaluation layer
read ``type``/``event``. Every metric evaluated to zero and the benchmark reported
0% attack success across every configuration for months.

Bug 2: ``new_run`` derived the run id from a second-resolution timestamp. A bench
sweep completes in milliseconds, so every run shared one directory - and therefore
one ``trace.jsonl``. Per-run metrics were actually cumulative.

Both are cheap to test and were completely untested.
"""

from __future__ import annotations

import json
from pathlib import Path

from aegis.core import events as ev
from aegis.core.events import EVENT_TYPE_FIELD, event_type
from aegis.core.run import new_run
from aegis.core.trace import TraceWriter


class TestEventTypeRoundTrip:
    def test_writer_and_reader_agree(self, tmp_path: Path) -> None:
        """The exact bug: what TraceWriter writes, event_type must read back."""
        writer = TraceWriter(run_dir=tmp_path / "run")
        writer.event(ev.TOOL_DECISION, tool_name="send_email", allowed=False)

        line = (tmp_path / "run" / "trace.jsonl").read_text().strip()
        record = json.loads(line)

        assert event_type(record) == ev.TOOL_DECISION

    def test_every_written_event_is_readable(self, tmp_path: Path) -> None:
        kinds = [
            ev.RUN_START,
            ev.SCENARIO_LOADED,
            ev.USER_MESSAGE,
            ev.ASSEMBLED_INSTRUCTION,
            ev.UNTRUSTED_CONTENT_RECEIVED,
            ev.DECODE_ATTEMPT,
            ev.DECODE_SUCCESS,
            ev.TOOL_DECISION,
            ev.TOOL_BLOCKED,
            ev.TOOL_RESULT,
            ev.RUN_END,
        ]
        writer = TraceWriter(run_dir=tmp_path / "run")
        for kind in kinds:
            writer.event(kind)

        records = [
            json.loads(line)
            for line in (tmp_path / "run" / "trace.jsonl").read_text().splitlines()
            if line.strip()
        ]

        assert [event_type(r) for r in records] == kinds

    def test_canonical_field_is_used(self, tmp_path: Path) -> None:
        writer = TraceWriter(run_dir=tmp_path / "run")
        writer.event(ev.AGENT_START)
        record = json.loads((tmp_path / "run" / "trace.jsonl").read_text().strip())
        assert EVENT_TYPE_FIELD in record

    def test_legacy_field_names_still_read(self) -> None:
        """Traces recorded by older versions must not silently evaluate to nothing."""
        assert event_type({"type": "tool_decision"}) == "tool_decision"
        assert event_type({"event": "tool_decision"}) == "tool_decision"

    def test_missing_type_returns_empty_string(self) -> None:
        assert event_type({"ts": "2026-01-01"}) == ""
        assert event_type({"kind": 42}) == ""


class TestRunIdUniqueness:
    def test_rapid_runs_get_distinct_directories(self, tmp_path: Path) -> None:
        """Twenty runs in the same second must not share a trace file."""
        contexts = [new_run(str(tmp_path)) for _ in range(20)]

        run_ids = {c.run_id for c in contexts}
        run_dirs = {c.run_dir for c in contexts}

        assert len(run_ids) == 20
        assert len(run_dirs) == 20

    def test_traces_do_not_accumulate_across_runs(self, tmp_path: Path) -> None:
        """Each run's trace holds only its own events."""
        for _ in range(5):
            ctx = new_run(str(tmp_path))
            ctx.trace.event(ev.TOOL_DECISION, tool_name="send_email", allowed=False)
            ctx.trace.event(ev.RUN_END, run_id=ctx.run_id)

        for run_dir in tmp_path.iterdir():
            lines = [
                line for line in (run_dir / "trace.jsonl").read_text().splitlines() if line.strip()
            ]
            # run_start + tool_decision + run_end
            assert len(lines) == 3
