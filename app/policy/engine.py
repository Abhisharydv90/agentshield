from fnmatch import fnmatch

from pydantic import BaseModel
from typing import Literal, Optional

from app.policy.dsl import Policy
from app.security.judge.contract import NormalizedToolCall


class PolicyVerdict(BaseModel):
    decision: Literal["allow", "deny", "step_up"]
    reason: str
    rule_matched: Optional[str] = None


def evaluate_policy(
    tool_call: NormalizedToolCall,
    policy: Policy,
) -> PolicyVerdict:
    """Evaluate rules deterministically, including explicit step-up flags."""
    for rule in policy.rules:
        if not fnmatch(tool_call.tool_name, rule.tool_pattern):
            continue

        if rule.op and rule.op != tool_call.op:
            continue

        if rule.target_denylist and tool_call.target:
            if any(
                fnmatch(tool_call.target, denied)
                for denied in rule.target_denylist
            ):
                return PolicyVerdict(
                    decision="deny",
                    reason=f"target_denied:{tool_call.target}",
                    rule_matched=rule.tool_pattern,
                )

        if rule.target_allowlist:
            if not tool_call.target:
                return PolicyVerdict(
                    decision="deny",
                    reason="target_missing_for_allowlist",
                    rule_matched=rule.tool_pattern,
                )
            if not any(
                fnmatch(tool_call.target, allowed)
                for allowed in rule.target_allowlist
            ):
                return PolicyVerdict(
                    decision="deny",
                    reason=f"target_not_in_allowlist:{tool_call.target}",
                    rule_matched=rule.tool_pattern,
                )

        # Enforce a configured row ceiling against the canonical argument
        # names used by database tools. If a bounded rule is configured but
        # the tool does not provide a numeric limit, fail closed.
        if rule.max_rows is not None:
            row_limit = None
            for key in ("max_rows", "limit", "row_limit"):
                candidate = tool_call.args_normalized.get(key)
                if candidate is not None:
                    try:
                        row_limit = int(candidate)
                    except (TypeError, ValueError):
                        return PolicyVerdict(
                            decision="deny",
                            reason=f"invalid_row_limit:{key}",
                            rule_matched=rule.tool_pattern,
                        )
                    break

            if row_limit is None:
                return PolicyVerdict(
                    decision="deny",
                    reason="row_limit_required",
                    rule_matched=rule.tool_pattern,
                )

            if row_limit > rule.max_rows:
                return PolicyVerdict(
                    decision="deny",
                    reason=f"max_rows_exceeded:{rule.max_rows}",
                    rule_matched=rule.tool_pattern,
                )

        # An explicit human-approval flag upgrades an allowable action.
        if rule.require_human_approval:
            if rule.decision == "deny":
                return PolicyVerdict(
                    decision="deny",
                    reason=f"rule_denied:{rule.tool_pattern}",
                    rule_matched=rule.tool_pattern,
                )
            return PolicyVerdict(
                decision="step_up",
                reason=f"rule_requires_human_approval:{rule.tool_pattern}",
                rule_matched=rule.tool_pattern,
            )

        if rule.decision == "allow":
            return PolicyVerdict(
                decision="allow",
                reason=f"rule_allowed:{rule.tool_pattern}",
                rule_matched=rule.tool_pattern,
            )

        if rule.decision == "deny":
            return PolicyVerdict(
                decision="deny",
                reason=f"rule_denied:{rule.tool_pattern}",
                rule_matched=rule.tool_pattern,
            )

        if rule.decision == "step_up":
            return PolicyVerdict(
                decision="step_up",
                reason=f"rule_step_up:{rule.tool_pattern}",
                rule_matched=rule.tool_pattern,
            )

    return PolicyVerdict(
        decision=policy.default,
        reason="policy_default",
        rule_matched=None,
    )
