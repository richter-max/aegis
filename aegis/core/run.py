from __future__ import annotations

import itertools
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from aegis.core import events as ev
from aegis.core.trace import TraceWriter

# Monotonic counter so runs started within the same second still get distinct ids.
# Without this, a bench sweep completes in milliseconds and every run shares one
# directory - and therefore one trace.jsonl, making per-run metrics meaningless.
_RUN_COUNTER = itertools.count(1)


@dataclass
class RunContext:
    run_id: str
    run_dir: Path
    trace: TraceWriter


def new_run(out_root: str = "runs") -> RunContext:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = f"{stamp}_{os.getpid():d}_{next(_RUN_COUNTER):04d}"
    run_dir = Path(out_root) / run_id

    trace = TraceWriter(run_dir=run_dir)
    trace.event(ev.RUN_START, run_id=run_id)

    return RunContext(run_id=run_id, run_dir=run_dir, trace=trace)
