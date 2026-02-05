from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

from aegis.core.run import RunContext


@dataclass(frozen=True)
class ToolCall:
    name: str
    args: Dict[str, Any]


class SearchLocalPageTool:
    """
    Simulates retrieval from an untrusted source (like the web).
    Reads a local HTML file from aegis/scenarios/pages/.
    """
    name = "search_local_page"

    def propose(self, page: str) -> ToolCall:
        return ToolCall(name=self.name, args={"page": page})

    def execute(self, ctx: RunContext, page: str) -> Dict[str, Any]:
        pages_dir = Path("aegis/scenarios/pages").resolve()
        path = (pages_dir / page).resolve()

        # Prevent path traversal
        if pages_dir not in path.parents and path != pages_dir:
            raise ValueError("Invalid page path (path traversal).")

        if not path.exists():
            raise FileNotFoundError(f"Page not found: {path}")

        html = path.read_text(encoding="utf-8", errors="replace")
        ctx.trace.event(
            "search_local_page",
            page=page,
            bytes=len(html.encode("utf-8", errors="replace")),
        )
        return {"page": page, "html": html}
