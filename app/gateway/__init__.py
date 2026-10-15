"""
AURAGENT Gateway public package.

The Gateway is the unified ingress/routing boundary.

It does not replace the Trust/Security Kernel.
It invokes security-aware downstream boundaries.
"""

from app.gateway.quotas import (
    GatewayQuotaManager,
    QuotaDecision,
    quota_manager,
)
from app.gateway.validation import (
    GatewayRequest,
    GatewayTarget,
    GatewayTargetKind,
)

__all__ = [
    "GatewayRequest",
    "GatewayTarget",
    "GatewayTargetKind",
    "GatewayQuotaManager",
    "QuotaDecision",
    "quota_manager",
]