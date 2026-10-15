from app.policy.dsl import Policy, ToolRule
from app.policy.engine import evaluate_policy
from app.security.judge.contract import NormalizedToolCall


def call(args):
    return NormalizedToolCall(
        tool_name="db.execute",
        op="write",
        target="billing_invoices",
        args_normalized=args,
    )


def test_max_rows_denies_missing_limit():
    policy = Policy(name="p", version="1", rules=[
        ToolRule(tool_pattern="db.execute", op="write", max_rows=1, decision="allow"),
    ])
    verdict = evaluate_policy(call({}), policy)
    assert verdict.decision == "deny"
    assert verdict.reason == "row_limit_required"


def test_max_rows_denies_excess_limit():
    policy = Policy(name="p", version="1", rules=[
        ToolRule(tool_pattern="db.execute", op="write", max_rows=1, decision="allow"),
    ])
    verdict = evaluate_policy(call({"limit": 2}), policy)
    assert verdict.decision == "deny"
    assert verdict.reason == "max_rows_exceeded:1"


def test_max_rows_allows_within_limit():
    policy = Policy(name="p", version="1", rules=[
        ToolRule(tool_pattern="db.execute", op="write", max_rows=1, decision="allow"),
    ])
    verdict = evaluate_policy(call({"limit": 1}), policy)
    assert verdict.decision == "allow"


def test_require_human_approval_upgrades_allow():
    policy = Policy(name="p", version="1", rules=[
        ToolRule(tool_pattern="db.execute", op="write", require_human_approval=True, decision="allow"),
    ])
    verdict = evaluate_policy(call({"limit": 1}), policy)
    assert verdict.decision == "step_up"
    assert verdict.reason.startswith("rule_requires_human_approval:")
