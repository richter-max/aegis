from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


def load_trace(trace_path: Path) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    with trace_path.open("r", encoding="utf-8") as f:
        for line in f:
            events.append(json.loads(line))
    return events


def simple_success_metrics(trace_path: Path) -> Dict[str, Any]:
    events = load_trace(trace_path)
    blocked = any(e.get("kind") == "tool_blocked" for e in events)
    executed = any(e.get("kind") == "send_email_mocked" for e in events)
    return {
        "tool_blocked": blocked,
        "email_executed_mocked": executed,
    }
