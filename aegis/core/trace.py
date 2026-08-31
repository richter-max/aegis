from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegis.core.events import EVENT_TYPE_FIELD


def utc_ts() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class TraceWriter:
    """Append-only JSONL writer. One trace file per run directory.

    The event type is stored under :data:`aegis.core.events.EVENT_TYPE_FIELD` and read
    back through :func:`aegis.core.events.event_type`. Do not hardcode the field name
    here or in the readers.
    """

    run_dir: Path

    def __post_init__(self) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.trace_path = self.run_dir / "trace.jsonl"

    def event(self, kind: str, **data: Any) -> None:
        record: dict[str, Any] = {"ts": utc_ts(), EVENT_TYPE_FIELD: kind, **data}
        with self.trace_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
