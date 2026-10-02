"""
Deterministic + probabilistic runtime tool-call authorization.

Pipeline:

    1. Normalize
    2. Validate normalized contract
    3. Enforce Agent capabilities
    4. Evaluate deterministic policy
    5. Optional LLM judge
    6. Audit

Security rule:

    Capability denial happens BEFORE the LLM judge.

An LLM cannot grant an Agent a capability that its identity does
not possess.
"""

from __future__ import annotations

import json
import uuid
from typing import Iterable

from google import genai
from google.genai import types
from pydantic import ValidationError
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.config import settings
from app.db.session import async_session
from app.policy.dsl import Policy
from app.policy.engine import evaluate_policy
from app.security.capabilities import (
    required_capabilities_for_operation,
    missing_capabilities,
)
from app.security.judge.contract import (
    JudgeVerdict,
    NormalizedToolCall,
)
from app.security.judge.normalize import (
    normalize_tool_call,
)
from app.telemetry.audit import write_event


JUDGE_SYSTEM = """
You are the AgentShield security judge.

You receive a normalized tool call and a deterministic policy.

Return STRICT JSON only:

{
  "decision": "allow|deny",
  "risk": 0.0,
  "reason": "short explanation",
  "category": "sqli|pii|destructive|exfil|privilege_escalation|benign|other",
  "policy_version": "version"
}

Rules:

- If uncertain, deny.
- DROP/TRUNCATE/DELETE without an appropriate restriction => deny.
- Writes to authentication, users, permissions, identity, or secrets
  tables should be treated as high risk unless explicitly authorized.
- Network calls to non-approved destinations should be denied.
- rm -rf, curl | sh, base64 -d | sh and equivalent command execution
  patterns should be denied.
- Potential data exfiltration should be denied.
"""


# ============================================================
# Judge client
# ============================================================


def _create_judge_client() -> genai.Client:

    if not settings.JUDGE_KEY:

        raise RuntimeError(
            "JUDGE_KEY is not configured"
        )

    return genai.Client(
        api_key=settings.JUDGE_KEY
    )


# ============================================================
# Main pipeline
# ============================================================


async def execute_tool_with_judge(
    raw_tool_call: dict,
    policy: Policy,
    policy_version: str,
    tenant_id: uuid.UUID,
    trace_id: str | None = None,
    agent_scopes: Iterable[str] | None = None,
) -> dict:

    scopes = list(
        agent_scopes or []
    )

    # ========================================================
    # Layer 1 — normalization
    # ========================================================

    normalized = normalize_tool_call(
        raw_tool_call
    )

    try:

        normalized_call = (
            NormalizedToolCall(
                **normalized
            )
        )

    except (
        ValueError,
        ValidationError,
    ):

        await _log(
            tenant_id,
            trace_id,
            "unauthorized_tool",
            "blocked",
            "normalization_rejected",
        )

        return {
            "decision":
                "deny",
            "reason":
                "normalization_rejected",
            "category":
                "other",
            "policy_version":
                policy_version,
        }

    # ========================================================
    # Layer 2 — operation validation
    # ========================================================

    if normalized_call.op == "unknown":

        await _log(
            tenant_id,
            trace_id,
            "unauthorized_tool",
            "blocked",
            "unknown_tool_operation",
        )

        return {
            "decision":
                "deny",
            "reason":
                "unknown_tool_operation",
            "category":
                "other",
            "policy_version":
                policy_version,
        }

    # ========================================================
    # Layer 3 — capability authorization
    # ========================================================

    required = (
        required_capabilities_for_operation(
            normalized_call.op
        )
    )

    missing = missing_capabilities(
        scopes,
        required,
    )

    if missing:

        reason = (
            "missing_capabilities:"
            + ",".join(missing)
        )

        await _log(
            tenant_id,
            trace_id,
            "privilege_escalation",
            "blocked",
            reason,
        )

        return {
            "decision":
                "deny",
            "reason":
                reason,
            "category":
                "privilege_escalation",
            "missing_capabilities":
                missing,
            "required_capabilities":
                [
                    capability.value
                    for capability in required
                ],
            "policy_version":
                policy_version,
        }

    # ========================================================
    # Layer 4 — deterministic policy
    # ========================================================

    policy_verdict = evaluate_policy(
        normalized_call,
        policy,
    )

    if policy_verdict.decision == "deny":

        await _log(
            tenant_id,
            trace_id,
            "unauthorized_tool",
            "blocked",
            policy_verdict.reason,
        )

        return {
            "decision":
                "deny",
            "reason":
                policy_verdict.reason,
            "category":
                "other",
            "policy_version":
                policy_version,
        }

    if policy_verdict.decision == "step_up":

        await _log(
            tenant_id,
            trace_id,
            "privilege_escalation",
            "step_up_approval",
            policy_verdict.reason,
        )

        return {
            "decision":
                "step_up",
            "reason":
                policy_verdict.reason,
            "category":
                "privilege_escalation",
            "policy_version":
                policy_version,
        }

    # ========================================================
    # Layer 5 — Judge control
    # ========================================================

    if (
        settings.KILL_JUDGE
        or not settings.JUDGE_ENFORCE
    ):

        reason = (
            "deterministic_policy_allow;"
            "llm_judge_disabled"
        )

        await _log(
            tenant_id,
            trace_id,
            "benign",
            "allowed",
            reason,
        )

        return {
            "decision":
                "allow",
            "risk":
                0.0,
            "reason":
                reason,
            "category":
                "benign",
            "policy_version":
                policy_version,
        }

    # ========================================================
    # Layer 6 — LLM judge
    # ========================================================

    client = _create_judge_client()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(
            multiplier=1,
            min=2,
            max=10,
        ),
        retry=retry_if_exception_type(
            Exception
        ),
        reraise=True,
    )
    async def _call_judge():

        return await client.aio.models.generate_content(
            model=settings.JUDGE_MODEL,
            contents=json.dumps(
                {
                    "tool_call":
                        normalized_call.model_dump(),
                    "policy":
                        policy.model_dump(),
                },
                ensure_ascii=False,
            ),
            config=types.GenerateContentConfig(
                system_instruction=
                    JUDGE_SYSTEM,
                temperature=0,
                response_mime_type=
                    "application/json",
            ),
        )

    try:

        response = await _call_judge()

        parsed = json.loads(
            response.text
        )

        verdict = JudgeVerdict(
            **parsed
        )

        # Prevent a judge from silently switching
        # to a different policy version.
        verdict.policy_version = (
            policy_version
        )

    except Exception as exc:

        verdict = JudgeVerdict(
            decision="deny",
            risk=1.0,
            category="other",
            reason=(
                "judge_failure_failclosed:"
                f"{str(exc)[:100]}"
            ),
            policy_version=
                policy_version,
        )

    # ========================================================
    # Layer 7 — audit
    # ========================================================

    action = (
        "blocked"
        if verdict.decision == "deny"
        else "allowed"
    )

    await _log(
        tenant_id,
        trace_id,
        verdict.category,
        action,
        verdict.reason,
    )

    return {
        "decision":
            verdict.decision,
        "reason":
            verdict.reason,
        "risk":
            verdict.risk,
        "category":
            verdict.category,
        "policy_version":
            verdict.policy_version,
    }


# ============================================================
# Audit
# ============================================================


async def _log(
    tenant_id: uuid.UUID,
    trace_id: str | None,
    threat_category: str,
    action_taken: str,
    reason: str,
) -> None:

    try:

        async with async_session() as session:

            await write_event(
                session=session,
                tenant_id=tenant_id,
                request_id=trace_id,
                threat_category=
                    threat_category,
                action_taken=
                    action_taken,
                evaluator_reasoning=
                    reason,
            )

    except Exception:
        # The audit layer is best-effort in the current phase.
        # We will harden this to fail closed with stronger
        # transactional guarantees in the Evidence/Audit phase.
        pass