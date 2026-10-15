"""Security-aware Tool Fabric dispatcher.

The dispatcher is the execution gate between an autonomous plan and an actual
tool. It never turns model output into authority and never bypasses the Phase 4
Security Kernel.
"""

from __future__ import annotations

from typing import Any

from app.security.context import SecurityContext
from app.security.kernel import SecurityKernel
from app.security.trust.risk import RiskScorer
from app.tools.contracts import ToolInvocation, ToolResult
from app.tools.registry import ToolNotFoundError, ToolRegistry, get_tool_registry
from app.tools.resources import ResourceAuthorizer


class ToolDispatcher:
    def __init__(
        self,
        registry: ToolRegistry | None = None,
        *,
        kernel: SecurityKernel | None = None,
        resources: ResourceAuthorizer | None = None,
        risk_scorer: RiskScorer | None = None,
    ) -> None:
        self.registry = registry or get_tool_registry()
        self.kernel = kernel or SecurityKernel()
        self.resources = resources or ResourceAuthorizer()
        self.risk_scorer = risk_scorer or RiskScorer()

    def _deny(
        self,
        invocation: ToolInvocation,
        reason: str,
        *,
        error_code: str | None = None,
        proof: dict[str, Any] | None = None,
    ) -> ToolResult:
        return ToolResult(
            decision="deny",
            reason=reason,
            tool_name=invocation.tool_name,
            operation=invocation.operation,
            call_id=invocation.call_id,
            proof=proof,
            error_code=error_code,
        )

    async def dispatch(
        self,
        invocation: ToolInvocation,
        context: SecurityContext,
    ) -> ToolResult:
        try:
            registered = self.registry.get(invocation.tool_name)
        except ToolNotFoundError:
            return self._deny(invocation, "tool_not_registered", error_code="tool_not_registered")

        manifest = registered.manifest
        operation = invocation.operation.strip()

        if not manifest.enabled:
            return self._deny(invocation, "tool_disabled", error_code="tool_disabled")

        if not manifest.supports(operation):
            return self._deny(invocation, "operation_not_supported", error_code="operation_not_supported")

        if operation not in context.authority.operations:
            return self._deny(invocation, "operation_outside_authority", error_code="operation_outside_authority")

        missing = manifest.required_capabilities.difference(context.capabilities)
        if missing:
            return self._deny(
                invocation,
                "missing_tool_capabilities:" + ",".join(sorted(missing)),
                error_code="missing_capabilities",
            )

        if invocation.resource:
            decision = self.resources.allows(context.authority, invocation.resource)
            if not decision.allowed:
                return self._deny(invocation, decision.reason, error_code="resource_denied")

        if manifest.resource_patterns:
            if not invocation.resource:
                return self._deny(invocation, "tool_requires_resource_binding", error_code="resource_required")
            allowed_pattern = any(
                invocation.resource == pattern
                or (pattern.endswith("/") and invocation.resource.startswith(pattern))
                for pattern in manifest.resource_patterns
            )
            if not allowed_pattern:
                return self._deny(invocation, "resource_not_supported_by_tool", error_code="tool_resource_denied")

        network_egress = bool(invocation.target_url)
        if network_egress:
            if "network:egress" not in context.capabilities:
                return self._deny(invocation, "network_egress_capability_required", error_code="network_denied")
            decision = self.resources.network_domain_allowed(context.authority, invocation.target_url or "")
            if not decision.allowed:
                return self._deny(invocation, decision.reason, error_code="network_denied")

        risk = self.risk_scorer.from_action(
            operation=operation,
            network_egress=network_egress,
            sensitive_resource=manifest.sensitive,
            destructive=manifest.destructive,
            external_content_influence=manifest.external_content,
        )

        action = {
            "schema": "auragent.tool-action.v1",
            "call_id": invocation.call_id,
            "tool": manifest.public_dict(),
            "invocation": invocation.public_dict(),
            "tenant_id": str(context.tenant_id),
            "agent_id": str(context.agent_id),
            "authority_token_hash": context.authority_token_hash,
            "policy_hash": context.policy_hash,
        }

        kernel_decision = self.kernel.authorize_action(
            context=context,
            action=action,
            required_capabilities=set(manifest.required_capabilities),
            risk_score=risk.score,
            policy_hash=context.policy_hash,
            approval_id=invocation.approval_id,
        )

        proof = kernel_decision.decision_proof.to_dict() if kernel_decision.decision_proof else None
        if not kernel_decision.allowed:
            decision = "approval_required" if kernel_decision.reason == "human_approval_required" else "deny"
            return ToolResult(
                decision=decision,
                reason=kernel_decision.reason,
                tool_name=invocation.tool_name,
                operation=operation,
                call_id=invocation.call_id,
                proof=proof,
                error_code="approval_required" if decision == "approval_required" else "authorization_denied",
                metadata={"risk_score": risk.score, "risk_level": risk.level.value},
            )

        try:
            value = registered.handler(invocation, context)
            if hasattr(value, "__await__"):
                value = await value
        except Exception as exc:
            # Never expose handler internals or secret-bearing exception text.
            return ToolResult(
                decision="error",
                reason="tool_execution_failed",
                tool_name=invocation.tool_name,
                operation=operation,
                call_id=invocation.call_id,
                proof=proof,
                error_code="tool_execution_failed",
                metadata={"risk_score": risk.score, "risk_level": risk.level.value},
            )

        return ToolResult(
            decision="allow",
            reason="tool_execution_completed",
            tool_name=invocation.tool_name,
            operation=operation,
            call_id=invocation.call_id,
            value=value,
            proof=proof,
            metadata={
                "risk_score": risk.score,
                "risk_level": risk.level.value,
                "tool_version": manifest.version,
            },
        )
