from pydantic import BaseModel, Field, model_validator
from typing import Literal, Optional

class NormalizedToolCall(BaseModel):
    tool_name: str
    op: Literal["read", "write", "delete", "execute", "external_call", "unknown"]
    target: Optional[str] = None
    args_normalized: dict = Field(default_factory=dict)
    contains_compound_statement: bool = False
    contains_comment_bypass: bool = False
    contains_encoded_payload: bool = False

    @model_validator(mode="after")
    def _reject_smuggling(self):
        if self.contains_compound_statement or self.contains_comment_bypass:
            raise ValueError("smuggling_detected")
        return self

class JudgeVerdict(BaseModel):
    decision: Literal["allow", "deny"]
    risk: float = Field(ge=0.0, le=1.0)
    category: Literal["sqli", "pii", "destructive", "exfil", "privilege_escalation", "benign", "other"]
    reason: str = Field(max_length=280)
    policy_version: str