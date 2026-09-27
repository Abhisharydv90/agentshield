import fnmatch
from app.policy.dsl import Policy, ToolRule
from app.security.judge.contract import NormalizedToolCall
from pydantic import BaseModel
from typing import Literal, Optional

class PolicyVerdict(BaseModel):
    decision: Literal["allow", "deny", "step_up"]
    reason: str
    rule_matched: Optional[str] = None

def evaluate_policy(tool_call: NormalizedToolCall, policy: Policy) -> PolicyVerdict:
    for rule in policy.rules:
        # 1. Match tool name pattern (e.g. "db.*")
        if not fnmatch.fnmatch(tool_call.tool_name, rule.tool_pattern):
            continue

        # 2. Match operation (if specified)
        if rule.op and rule.op != tool_call.op:
            continue

        # 3. Check denylist (highest priority)
        if rule.target_denylist and tool_call.target:
            if any(fnmatch.fnmatch(tool_call.target, d) for d in rule.target_denylist):
                return PolicyVerdict(decision="deny", reason=f"target_denied:{tool_call.target}", rule_matched=rule.tool_pattern)

        # 4. Check allowlist
        if rule.target_allowlist:
            if not tool_call.target:
                return PolicyVerdict(decision="deny", reason="target_missing_for_allowlist", rule_matched=rule.tool_pattern)
            if not any(fnmatch.fnmatch(tool_call.target, a) for a in rule.target_allowlist):
                return PolicyVerdict(decision="deny", reason=f"target_not_in_allowlist:{tool_call.target}", rule_matched=rule.tool_pattern)

        # 5. If rule matches, return its decision
        if rule.decision == "allow":
            return PolicyVerdict(decision="allow", reason=f"rule_allowed:{rule.tool_pattern}", rule_matched=rule.tool_pattern)
        elif rule.decision == "deny":
            return PolicyVerdict(decision="deny", reason=f"rule_denied:{rule.tool_pattern}", rule_matched=rule.tool_pattern)
        elif rule.decision == "step_up":
            return PolicyVerdict(decision="step_up", reason=f"rule_step_up:{rule.tool_pattern}", rule_matched=rule.tool_pattern)

    # 6. Fallback to policy default
    return PolicyVerdict(decision=policy.default, reason="policy_default", rule_matched=None)