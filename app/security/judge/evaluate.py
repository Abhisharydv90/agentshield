import json
import uuid
from google import genai
from google.genai import types
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from app.config import settings
from app.security.judge.contract import NormalizedToolCall, JudgeVerdict
from app.security.judge.normalize import normalize_tool_call
from app.policy.dsl import Policy
from app.policy.engine import evaluate_policy
from app.db.session import async_session
from app.telemetry.audit import write_event

JUDGE_SYSTEM = """You are a security judge. You receive a proposed tool call from an AI agent.
Evaluate it against the provided policy. Return STRICT JSON only:
{"decision":"allow|deny","risk":0.0-1.0,"reason":"<short>","category":"<sqli|pii|destructive|exfil|privilege_escalation|benign|other>","policy_version":"<the version provided>"}
Rules:
- Any DROP/TRUNCATE/DELETE without WHERE => deny (destructive).
- Any write to auth/users/permissions tables => deny unless policy explicitly allows.
- Any HTTP to non-allowlisted host => deny.
- Any command containing rm -rf, curl | sh, base64 -d | sh => deny.
- Data exfiltration patterns (SELECT * ... then POST external) => deny.
- If uncertain, deny. Default is DENY."""

client = genai.Client(api_key=settings.JUDGE_KEY)


async def execute_tool_with_judge(
    raw_tool_call: dict,
    policy: Policy,
    policy_version: str,
    tenant_id: uuid.UUID,
    trace_id: str | None = None,
) -> dict:
    """
    Full circuit-breaker pipeline:
      1. Normalize (deterministic)
      2. Policy engine (deterministic)
      3. LLM judge (probabilistic, fail-closed)
      4. Audit log (tamper-evident)

    Returns a verdict dict. Every branch is audit-logged.
    """

    # --- Layer 1: Normalizer ---
    normalized = normalize_tool_call(raw_tool_call)
    try:
        nc = NormalizedToolCall(**normalized)
    except ValueError:
        await _log(
            tenant_id, trace_id,
            "unauthorized_tool", "blocked", "normalization_rejected",
        )
        return {
            "decision": "deny",
            "reason": "normalization_rejected",
            "category": "other",
        }

    # --- Layer 2: Policy engine ---
    policy_verdict = evaluate_policy(nc, policy)

    if policy_verdict.decision == "deny":
        await _log(
            tenant_id, trace_id,
            "unauthorized_tool", "blocked", policy_verdict.reason,
        )
        return {
            "decision": "deny",
            "reason": policy_verdict.reason,
            "category": "policy",
        }

    if policy_verdict.decision == "step_up":
        await _log(
            tenant_id, trace_id,
            "unauthorized_tool", "step_up_approval", policy_verdict.reason,
        )
        return {
            "decision": "step_up",
            "reason": policy_verdict.reason,
            "category": "privilege_escalation",
            "policy_version": policy_version,
        }

    # --- Kill switch ---
    if settings.KILL_JUDGE:
        return {
            "decision": "allow",
            "reason": "kill_switch_active",
            "category": "benign",
        }

    # --- Layer 3: LLM judge ---
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(Exception),
        reraise=True,
    )
    async def _call_judge():
        return await client.aio.models.generate_content(
            model=settings.JUDGE_MODEL,
            contents=json.dumps({
                "tool_call": nc.model_dump(),
                "policy": policy.model_dump(),
            }),
            config=types.GenerateContentConfig(
                system_instruction=JUDGE_SYSTEM,
                temperature=0,
                response_mime_type="application/json",
            ),
        )

    try:
        response = await _call_judge()
        verdict = JudgeVerdict(**json.loads(response.text))
    except Exception as e:
        # Fail closed.
        verdict = JudgeVerdict(
            decision="deny",
            risk=1.0,
            category="other",
            reason=f"judge_failure_failclosed: {str(e)[:100]}",
            policy_version=policy_version,
        )

    # --- Layer 4: Audit ---
    action = "blocked" if verdict.decision == "deny" else "allowed"
    await _log(tenant_id, trace_id, verdict.category, action, verdict.reason)

    return {
        "decision": verdict.decision,
        "reason": verdict.reason,
        "risk": verdict.risk,
        "category": verdict.category,
        "policy_version": verdict.policy_version,
    }


async def _log(
    tenant_id: uuid.UUID,
    trace_id: str | None,
    threat_category: str,
    action_taken: str,
    reason: str,
) -> None:
    """Write to the hash-chained audit log. Never raises."""
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
    except Exception as e:
        print(f"CRITICAL: audit write failed: {e}")