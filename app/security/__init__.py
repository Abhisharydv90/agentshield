"""AURAGENT Trust & Security Kernel.

The package keeps four concepts deliberately separate:

    identity != authority != influence != evidence

Phase 4 provides the stable trust contracts consumed by later phases.
AgentShield remains the runtime enforcement component inside this kernel.
"""

from app.security.kernel import (
    KernelDecision,
    SecurityKernel,
)

__all__ = ["KernelDecision", "SecurityKernel"]
