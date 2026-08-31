from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegis.core.run import RunContext

#: Resolved from the package location, not the working directory, so the harness
#: runs correctly regardless of where it is invoked from.
PAGES_DIR = (Path(__file__).resolve().parent.parent / "scenarios" / "pages").resolve()


@dataclass(frozen=True)
class ToolCall:
    name: str
    args: dict[str, Any]


class SearchLocalPageTool:
    """Simulates retrieval from an untrusted source such as the web.

    Reads a local HTML file from ``aegis/scenarios/pages/``. Content returned by this
    tool is untrusted by definition: it is the injection vector the harness exercises.
    """

    name = "search_local_page"

    def propose(self, page: str) -> ToolCall:
        return ToolCall(name=self.name, args={"page": page})

    def execute(self, ctx: RunContext, page: str) -> dict[str, Any]:
        path = (PAGES_DIR / page).resolve()

        # Reject anything that escapes the pages directory.
        if path.parent != PAGES_DIR:
            raise ValueError(f"Invalid page path (path traversal attempt): {page!r}")

        if not path.is_file():
            raise FileNotFoundError(f"Page not found: {path}")

        html = path.read_text(encoding="utf-8", errors="replace")
        ctx.trace.event(
            "search_local_page",
            page=page,
            bytes=len(html.encode("utf-8", errors="replace")),
        )
        return {"page": page, "html": html}
