from pydantic import BaseModel, Field
from typing import Literal, Optional


class ToolRule(BaseModel):
    tool_pattern: str
    op: Optional[Literal["read", "write", "delete", "execute", "external_call", "unknown"]] = None
    target_allowlist: list[str] = Field(default_factory=list)
    target_denylist: list[str] = Field(default_factory=list)
    max_rows: Optional[int] = None
    require_human_approval: bool = False
    decision: Literal["allow", "deny", "step_up"] = "deny"


class Policy(BaseModel):
    name: str
    version: str
    default: Literal["allow", "deny"] = "deny"
    rules: list[ToolRule]
    notes: str = ""


EXAMPLE_POLICY = Policy(
    name="test-billing-agent",
    version="1.0.0",
    default="deny",
    rules=[
        ToolRule(tool_pattern="db.query", op="read", target_allowlist=["billing_*", "users"], decision="allow"),
        ToolRule(tool_pattern="db.query", op="delete", decision="deny"),
        ToolRule(tool_pattern="db.execute", op="write", target_allowlist=["billing_invoices"], max_rows=1, decision="allow"),
        ToolRule(tool_pattern="email.send", op="external_call", decision="step_up"),
        ToolRule(tool_pattern="*", decision="deny"),
    ],
)