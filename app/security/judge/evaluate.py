import json
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

# Configure the new Google GenAI Client with the stable v1 API
client = genai.Client(api_key=settings.JUDGE_KEY)

async def execute_tool_with_judge(raw_tool_call: dict, policy: Policy, policy_version: str) -> dict:
    """
    The full circuit breaker pipeline:
    1. Normalize
    2. Policy Engine (deterministic)
    3. LLM Judge (probabilistic)
    4. Audit Log (tamper-evident)
    Returns a decision dict and logs everything.
    """
    trace_id = None
    
    # --- Layer 1: Normalizer ---
    normalized = normalize_tool_call(raw_tool_call)
    try:
        nc = NormalizedToolCall(**normalized)
    except ValueError:
        await _log(trace_id, "unauthorized_tool", "blocked", "normalization_rejected")
        return {"decision": "deny", "reason": "normalization_rejected", "category": "other"}

       # --- Layer 2: Policy Engine ---
    policy_verdict = evaluate_policy(nc, policy)

    if policy_verdict.decision == "deny":
        await _log(trace_id, "unauthorized_tool", "blocked", policy_verdict.reason)
        return {"decision": "deny", "reason": policy_verdict.reason, "category": "policy"}

    if policy_verdict.decision == "step_up":
        await _log(trace_id, "unauthorized_tool", "step_up_approval", policy_verdict.reason)
        return {
            "decision": "step_up",
            "reason": policy_verdict.reason,
            "category": "privilege_escalation",
            "policy_version": policy_version,
        }
    # --- Layer 3: LLM Judge (unless kill switch is on) ---
    if settings.KILL_JUDGE:
        return {"decision": "allow", "reason": "kill_switch_active", "category": "benign"}

    # Retry logic for transient API failures (503, 429)
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(Exception),
        reraise=True
    )
    async def _call_judge():
        model_name = settings.JUDGE_MODEL
        return await client.aio.models.generate_content(
            model=model_name,
            contents=json.dumps({"tool_call": nc.model_dump(), "policy": policy.model_dump()}),
            config=types.GenerateContentConfig(
                system_instruction=JUDGE_SYSTEM,
                temperature=0,
                response_mime_type="application/json",
            )
        )

    try:
        response = await _call_judge()
        raw_verdict = response.text
        verdict = JudgeVerdict(**json.loads(raw_verdict))
    except Exception as e:
        # Fail closed. If the judge errors after retries, we deny.
        verdict = JudgeVerdict(
            decision="deny", 
            risk=1.0, 
            category="other",
            reason=f"judge_failure_failclosed: {str(e)[:100]}", 
            policy_version=policy_version
        )

        # --- Layer 4: Audit Log ---
    action = "blocked" if verdict.decision == "deny" else "allowed"
    await _log(trace_id, verdict.category, action, verdict.reason)

    return {
        "decision": verdict.decision,
        "reason": verdict.reason,
        "risk": verdict.risk,
        "category": verdict.category,
        "policy_version": verdict.policy_version,
    }

async def _log(trace_id, threat_category: str, action_taken: str, reason: str):
    """Helper to write to the hash-chained audit log."""
    async with async_session() as session:
        await write_event(
            session=session,
            request_id=trace_id,
            threat_category=threat_category,
            action_taken=action_taken,
            evaluator_reasoning=reason,
        )