"""P1 policy-integrity regression coverage."""

import pytest
from pydantic import ValidationError

from app.policy.dsl import ToolRule


def test_policy_rule_rejects_unknown_decision():
    with pytest.raises(ValidationError):
        ToolRule(tool_pattern="tool.x", decision="allow_all")


def test_policy_rule_rejects_unknown_operation():
    with pytest.raises(ValidationError):
        ToolRule(tool_pattern="tool.x", op="grant")


def test_policy_rule_requires_nonempty_pattern():
    with pytest.raises(ValidationError):
        ToolRule(tool_pattern="", decision="deny")


def test_policy_model_has_one_active_policy_partial_index():
    indexes = {index.name: index for index in __import__("app.db.models", fromlist=["Policy"]).Policy.__table__.indexes}
    index = indexes["uq_policies_tenant_active"]
    assert index.unique is True
