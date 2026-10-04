"""
Deterministic + probabilistic runtime tool-call authorization.

Pipeline:

    1. Normalize
    2. Validate normalized contract
    3. Security Decision Engine
    4. Deterministic policy
    5. Optional LLM judge
    6. Audit

The Security Decision Engine is the authoritative runtime identity and
capability boundary when `agent_id` is supplied.

Important security rule:

    The LLM judge can evaluate risk.
    It cannot grant capabilities that the Agent does not possess.
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
from app.security.decision.contract import (
    SecurityAction,
    SecurityDecision,
)
from app.security.decision.engine import (
    SecurityDecisionEngine,
)
from app.security.evidence.binding import (
    approval_decision_hash,
    capability_snapshot_hash,
    policy_snapshot_hash,
)
from app.security.judge.contract import (
    JudgeVerdict,
    NormalizedToolCall,
)
from app.security.judge.normalize import (
    normalize_tool_call,
)
from app.telemetry.audit import write_event


# ============================================================
# Judge system instruction
# ============================================================

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

The deterministic policy and Agent capabilities are authoritative.
Never assume an LLM can grant an Agent a missing capability.
"""


# ============================================================
# Judge client
# ============================================================

def _create_judge_client() -> genai.Client:
    """
    Create the provider client only when the probabilistic judge
    is actually required.
    """

    if not settings.JUDGE_KEY:
        raise RuntimeError(
            "JUDGE_KEY is not configured"
        )

    return genai.Client(
        api_key=settings.JUDGE_KEY
    )


# ============================================================
# Decision-engine action construction
# ============================================================

def _build_security_action(
    *,
    normalized_call: NormalizedToolCall,
    policy: Policy,
    policy_version: str,
    tenant_id: uuid.UUID,
    agent_id: uuid.UUID,
    trace_id: str | None,
    agent_scopes: Iterable[str],
) -> SecurityAction:
    """
    Construct the canonical action presented to the Security Decision
    Engine.

    The fingerprint is based on the effective normalized action rather
    than provider-specific wrapper data.
    """

    required = required_capabilities_for_operation(
        normalized_call.op
    )

    return SecurityAction(
        tenant_id=tenant_id,
        agent_id=agent_id,
        trace_id=trace_id or "",
        tool_name=normalized_call.tool_name,
        operation=normalized_call.op,
        target=normalized_call.target,
        arguments=normalized_call.args_normalized,
        capabilities=[
            capability.value
            for capability in required
        ],
        policy_version=policy_version,
        policy_hash=policy_snapshot_hash(policy),
        capability_snapshot_hash=capability_snapshot_hash(
            tenant_id=tenant_id,
            agent_id=agent_id,
            status="active",
            scopes=agent_scopes,
        ),
        provenance={
            "source": "judge_pipeline",
            "normalization": "deterministic",
        },
    )


async def _authorize_with_decision_engine(
    *,
    action: SecurityAction,
) -> dict | None:
    """
    Ask the persisted Security Decision Engine whether the Agent identity
    is permitted to reach the next stage.

    Returns None when authorization succeeds.

    Returns a structured denial when the security kernel blocks the action.
    """

    async with async_session() as session:

        engine = SecurityDecisionEngine(
            session
        )

        result = await engine.authorize(
            action
        )

        if result.decision == (
            SecurityDecision.ALLOW
        ):
            return None

        await _log(
            action.tenant_id,
            action.trace_id,
            "privilege_escalation",
            "blocked",
            result.reason,
        )

        return {
            "decision": result.decision.value,
            "reason": result.reason,
            "category": (
                "privilege_escalation"
            ),
            "missing_capabilities": (
                result.missing_capabilities
            ),
            "action_fingerprint": result.action_fingerprint,
            "policy_hash": result.policy_hash,
            "capability_snapshot_hash": result.capability_snapshot_hash,
            "decision_hash": result.decision_hash,
        }


async def _request_human_approval(
    *,
    action: SecurityAction,
) -> dict:
    """
    Persist an approval request for a policy `step_up` result.

    The request is committed before the result is returned, so the
    approval_id is durable and can safely be handed to a separate
    human-control-plane request.
    """

    async with async_session() as session:

        engine = SecurityDecisionEngine(
            session
        )

        result = await engine.authorize(
            action,
            require_human_approval=True,
        )

        await session.commit()

        await _log(
            action.tenant_id,
            action.trace_id,
            "privilege_escalation",
            "step_up_approval",
            result.reason,
        )

        return {
            "decision": result.decision.value,
            "reason": result.reason,
            "category": (
                "privilege_escalation"
            ),
            "policy_version": (
                action.policy_version
            ),
            "approval_id": (
                str(result.approval_id)
                if result.approval_id
                else None
            ),
            "action_fingerprint": result.action_fingerprint,
            "policy_hash": result.policy_hash,
            "capability_snapshot_hash": result.capability_snapshot_hash,
            "decision_hash": result.decision_hash,
        }



# ============================================================
# Approval consumption
# ============================================================

def _parse_approval_id(
    approval_id: str | uuid.UUID | None,
) -> uuid.UUID | None:
    """Parse the runtime approval identifier without accepting arbitrary text."""
    if approval_id is None:
        return None

    if isinstance(approval_id, uuid.UUID):
        return approval_id

    try:
        return uuid.UUID(str(approval_id))
    except (ValueError, AttributeError, TypeError):
        return None


def _action_with_approval_trace(
    *,
    action: SecurityAction,
    approval_trace_id: str,
) -> SecurityAction:
    """
    Rebuild the same security action using the trace ID bound to the
    persisted approval.

    trace_id is an event/request identifier. The approval fingerprint is
    bound to the original action context, so a legitimate retry may have a
    fresh transport trace while still referring to the exact approved action.
    """
    return SecurityAction(
        tenant_id=action.tenant_id,
        agent_id=action.agent_id,
        trace_id=approval_trace_id,
        tool_name=action.tool_name,
        operation=action.operation,
        target=action.target,
        arguments=action.arguments,
        capabilities=action.capabilities,
        policy_version=action.policy_version,
        provenance=action.provenance,
        policy_hash=action.policy_hash,
        capability_snapshot_hash=action.capability_snapshot_hash,
    )


async def _consume_approval(
    *,
    action: SecurityAction,
    approval_id: str | uuid.UUID,
) -> dict | None:
    """
    Consume one approved artifact exactly once.

    Returns None when consumption succeeds. Otherwise returns a structured
    denial. The engine performs tenant scoping, exact fingerprint matching,
    state validation, expiry validation, and the one-time state transition.
    """
    parsed_id = _parse_approval_id(approval_id)
    if parsed_id is None:
        return {
            "decision": "deny",
            "reason": "approval_invalid_id",
            "category": "privilege_escalation",
            "approval_id": str(approval_id)[:128],
            "action_fingerprint": action.fingerprint(),
        }

    async with async_session() as session:
        engine = SecurityDecisionEngine(session)

        approval = await engine.get_approval(
            parsed_id,
            action.tenant_id,
        )

        if approval is None:
            return {
                "decision": "deny",
                "reason": "approval_not_found",
                "category": "privilege_escalation",
                "approval_id": str(parsed_id),
                "action_fingerprint": action.fingerprint(),
            }

        expected_action = _action_with_approval_trace(
            action=action,
            approval_trace_id=approval.trace_id,
        )
        expected_fingerprint = expected_action.fingerprint()

        expected_decision_hash = approval_decision_hash(
            action_fingerprint=expected_fingerprint,
            policy_hash=expected_action.policy_hash,
            capability_snapshot_hash=expected_action.capability_snapshot_hash,
        )

        try:
            consumed = await engine.consume(
                approval_id=parsed_id,
                tenant_id=action.tenant_id,
                expected_action_fingerprint=expected_fingerprint,
                expected_policy_hash=expected_action.policy_hash,
                expected_capability_snapshot_hash=expected_action.capability_snapshot_hash,
                expected_decision_hash=expected_decision_hash,
            )
            await session.commit()
        except ValueError as exc:
            await session.rollback()
            return {
                "decision": "deny",
                "reason": f"approval_consumption_failed:{str(exc)}",
                "category": "privilege_escalation",
                "approval_id": str(parsed_id),
                "action_fingerprint": expected_fingerprint,
                "policy_version": action.policy_version,
            }

        return {
            "_consumed": True,
            "approval_id": str(consumed.approval_id),
            "action_fingerprint": consumed.action_fingerprint,
            "policy_hash": consumed.policy_hash,
            "capability_snapshot_hash": consumed.capability_snapshot_hash,
            "decision_hash": consumed.decision_hash,
        }


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
    agent_id: uuid.UUID | None = None,
    approval_id: str | uuid.UUID | None = None,
) -> dict:
    """
    Full runtime security pipeline.

    When `agent_id` is supplied:

        normalize
          ->
        Security Decision Engine
          ->
        policy
          ->
        judge

    The database Agent record is authoritative for identity and
    capability checks.

    When `agent_id` is omitted, the established compatibility path
    continues to use the supplied `agent_scopes`. This preserves older
    callers while the HTTP runtime is migrated in a later batch.
    """

    scopes = list(
        agent_scopes or []
    )
    approved_continuation = False

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
            "decision": "deny",
            "reason": "normalization_rejected",
            "category": "other",
            "policy_version": policy_version,
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
            "decision": "deny",
            "reason": "unknown_tool_operation",
            "category": "other",
            "policy_version": policy_version,
        }

    # ========================================================
    # Layer 3 — Security Decision Engine
    # ========================================================

    if agent_id is not None:

        action = _build_security_action(
            normalized_call=normalized_call,
            policy=policy,
            policy_version=policy_version,
            tenant_id=tenant_id,
            agent_id=agent_id,
            trace_id=trace_id,
            agent_scopes=scopes,
        )

        decision_result = (
            await _authorize_with_decision_engine(
                action=action
            )
        )

        if decision_result is not None:

            decision_result[
                "policy_version"
            ] = policy_version

            return decision_result

    else:

        # ----------------------------------------------------
        # Compatibility capability path
        # ----------------------------------------------------

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
                "decision": "deny",
                "reason": reason,
                "category": (
                    "privilege_escalation"
                ),
                "missing_capabilities": missing,
                "required_capabilities": [
                    capability.value
                    for capability in required
                ],
                "policy_version": policy_version,
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
            "decision": "deny",
            "reason": policy_verdict.reason,
            "category": "other",
            "policy_version": policy_version,
        }

    if policy_verdict.decision == "step_up":

        # ----------------------------------------------------
        # New engine path
        # ----------------------------------------------------

        if agent_id is not None:

            action = _build_security_action(
                normalized_call=normalized_call,
                policy=policy,
                policy_version=policy_version,
                tenant_id=tenant_id,
                agent_id=agent_id,
                trace_id=trace_id,
                agent_scopes=scopes,
            )

            if approval_id is not None:
                # A supplied approval may only be consumed for a policy
                # step-up action. We defer consumption until the remaining
                # runtime checks have passed so a judge denial does not burn
                # the approval artifact.
                approved_continuation = True

            else:
                return await _request_human_approval(
                    action=action
                )

        else:

            # ------------------------------------------------
            # Compatibility path
            # ------------------------------------------------

            await _log(
                tenant_id,
                trace_id,
                "privilege_escalation",
                "step_up_approval",
                policy_verdict.reason,
            )

            return {
                "decision": "step_up",
                "reason": policy_verdict.reason,
                "category": (
                    "privilege_escalation"
                ),
                "policy_version": policy_version,
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

        if approved_continuation:
            consumed = await _consume_approval(
                action=action,
                approval_id=approval_id,  # type: ignore[arg-type]
            )
            if consumed is not None:
                consumed["policy_version"] = policy_version
                consumed["trace_id"] = trace_id

                # A successful consume is an authorization result, so expose
                # the fingerprint of the persisted artifact, not the fresh
                # transport-trace variant of the action.
                if consumed.get("_consumed") is True:
                    await _log(
                        tenant_id,
                        trace_id,
                        "privilege_escalation",
                        "allowed",
                        "approved_action_consumed",
                    )
                    return {
                        "decision": "allow",
                        "risk": 0.0,
                        "reason": (
                            "deterministic_policy_allow;"
                            "llm_judge_disabled;"
                            "approved_action_consumed"
                        ),
                        "category": "benign",
                        "policy_version": policy_version,
                        "approval_id": consumed.get("approval_id"),
                        "action_fingerprint": consumed.get(
                            "action_fingerprint"
                        ),
                        "trace_id": trace_id,
                    }

                await _log(
                    tenant_id,
                    trace_id,
                    "privilege_escalation",
                    "blocked",
                    consumed["reason"],
                )
                return consumed

        await _log(
            tenant_id,
            trace_id,
            "benign",
            "allowed",
            reason,
        )

        return {
            "decision": "allow",
            "risk": 0.0,
            "reason": reason,
            "category": "benign",
            "policy_version": policy_version,
            "approval_id": (
                str(approval_id)
                if approved_continuation and approval_id
                else None
            ),
            "action_fingerprint": (
                action.fingerprint()
                if approved_continuation
                else None
            ),
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
                system_instruction=JUDGE_SYSTEM,
                temperature=0,
                response_mime_type=(
                    "application/json"
                ),
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

        # The supplied runtime policy version is authoritative.
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
            policy_version=(
                policy_version
            ),
        )

    # ========================================================
    # Approval consumption
    # ========================================================

    consumed_fingerprint: str | None = None

    if (
        approved_continuation
        and verdict.decision == "allow"
    ):

        consumed = await _consume_approval(
            action=action,
            approval_id=approval_id,  # type: ignore[arg-type]
        )

        if consumed is not None:
            consumed["policy_version"] = policy_version
            consumed["trace_id"] = trace_id

            if consumed.get("_consumed") is True:
                consumed_fingerprint = consumed.get(
                    "action_fingerprint"
                )
            else:
                await _log(
                    tenant_id,
                    trace_id,
                    "privilege_escalation",
                    "blocked",
                    consumed["reason"],
                )

                return consumed

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
        "decision": verdict.decision,
        "reason": verdict.reason,
        "risk": verdict.risk,
        "category": verdict.category,
        "policy_version": verdict.policy_version,
        "approval_id": (
            str(approval_id)
            if approved_continuation and approval_id
            else None
        ),
        "action_fingerprint": (
            consumed_fingerprint
            if consumed_fingerprint is not None
            else (
                action.fingerprint()
                if approved_continuation
                else None
            )
        ),
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
    """Persist a security decision before the decision is returned.

    Audit persistence is part of the security boundary. A missing evidence
    record must not silently become a successful runtime action.
    """
    try:
        async with async_session() as session:
            await write_event(
                session=session,
                tenant_id=tenant_id,
                request_id=trace_id,
                threat_category=threat_category,
                action_taken=action_taken,
                evaluator_reasoning=reason,
            )
    except Exception as exc:
        raise RuntimeError("security_audit_unavailable") from exc
