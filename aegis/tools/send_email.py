from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from aegis.core.run import RunContext


@dataclass(frozen=True)
class ToolCall:
    name: str
    args: Dict[str, Any]


class SendEmailTool:
    name = "send_email"

    def propose(self, to: str, subject: str, body: str) -> ToolCall:
        return ToolCall(
            name=self.name,
            args={"to": to, "subject": subject, "body": body},
        )

    def execute(self, ctx: RunContext, to: str, subject: str, body: str) -> Dict[str, Any]:
        # Mock side-effect: only log
        ctx.trace.event("send_email_mocked", to=to, subject=subject, body_preview=body[:80])
        return {"status": "mocked", "to": to}
