from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


def utc_ts() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class TraceWriter:
    run_dir: Path

    def __post_init__(self) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.trace_path = self.run_dir / "trace.jsonl"

    def event(self, kind: str, **data: Any) -> None:
        record: Dict[str, Any] = {"ts": utc_ts(), "kind": kind, **data}
        with self.trace_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

