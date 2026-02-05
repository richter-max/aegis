from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from aegis.core.trace import TraceWriter


@dataclass
class RunContext:
    run_id: str
    run_dir: Path
    trace: TraceWriter


def new_run(out_root: str = "runs") -> RunContext:
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = Path(out_root) / run_id

    trace = TraceWriter(run_dir=run_dir)
    trace.event("run_start", run_id=run_id)

    return RunContext(run_id=run_id, run_dir=run_dir, trace=trace)

