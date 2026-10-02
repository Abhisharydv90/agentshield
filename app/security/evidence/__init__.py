"""
Evidence graph primitives for AgentShield.

The evidence layer records cryptographically identifiable security
artifacts and causal relationships between them.

Raw secrets and raw PII must never be placed into evidence metadata.
"""

from app.security.evidence.hashing import (
    canonicalize_evidence,
    fingerprint_evidence,
)

__all__ = [
    "canonicalize_evidence",
    "fingerprint_evidence",
]