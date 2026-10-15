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
