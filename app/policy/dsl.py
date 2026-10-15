from pydantic import BaseModel, Field
from typing import Literal, Optional


class ToolRule(BaseModel):
    tool_pattern: str
    op: Optional[Literal[
        "read", "write", "delete", "execute", "external_call", "unknown"
    ]] = None
    target_allowlist: list[str] = Field(default_factory=list)
    target_denylist: list[str] = Field(default_factory=list)
    max_rows: Optional[int] = Field(default=None, ge=1)
    require_human_approval: bool = False
    decision: Literal["allow", "deny", "step_up"] = "deny"


class Policy(BaseModel):
    name: str
    version: str
    default: Literal["allow", "deny"] = "deny"
    rules: list[ToolRule]
    notes: str = ""


NO_ACTIVE_POLICY = Policy(
    name="no-active-policy",
    version="0",
    default="deny",
    rules=[ToolRule(tool_pattern="*", decision="deny")],
)


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


def policy_from_db_rules(
    rules: list[dict] | None,
    name: str = "tenant-policy",
    version: str = "1.0.0",
    default: Literal["allow", "deny"] = "deny",
) -> Policy:
    """
    Convert the JSONB `rules` array stored on a Policy row into a runtime
    Policy object the engine can evaluate.

    Unknown fields in each rule dict are ignored. Malformed rules are
    skipped rather than raising — a partially-broken policy should still
    enforce the rules it can parse, and fall through to the catch-all deny.

    A catch-all `*: deny` rule is appended if not already present, so a
    tenant with an empty rules array still fails closed.
    """
    parsed: list[ToolRule] = []
    for raw in rules or []:
        if not isinstance(raw, dict):
            continue
        try:
            parsed.append(
                ToolRule(
                    tool_pattern=raw.get("tool_pattern") or "*",
                    op=raw.get("op") or None,
                    target_allowlist=raw.get("target_allowlist") or [],
                    target_denylist=raw.get("target_denylist") or [],
                    max_rows=raw.get("max_rows"),
                    require_human_approval=bool(
                        raw.get("require_human_approval", False)
                    ),
                    decision=raw.get("decision") or "deny",
                )
            )
        except Exception:
            continue

    if not any(r.tool_pattern == "*" for r in parsed):
        parsed.append(ToolRule(tool_pattern="*", decision="deny"))

    return Policy(
        name=name,
        version=version,
        default=default,
        rules=parsed,
    )