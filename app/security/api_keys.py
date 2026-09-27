"""
API key generation, hashing, and verification.

Keys are never stored in plaintext. We store the SHA-256 hash of the key.
Verification is done by hashing the provided key and comparing against the
stored hash — constant-time comparison to avoid timing attacks.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import string

# ============================================================
# Format
# ============================================================
# Live keys:   ask_live_<40 random chars>
# Test keys:   ask_test_<40 random chars>
# Prefix shown to the user: first 16 chars of the full key

_PREFIX_LIVE = "ask_live_"
_PREFIX_TEST = "ask_test_"
# Unambiguous alphabet — excludes 0/O, 1/I/l to prevent copy-paste errors
_ALPHABET = (
    "ABCDEFGHJKLMNPQRSTUVWXYZ"   # no I, O
    "abcdefghijkmnopqrstuvwxyz"  # no l
    "23456789"                    # no 0, 1
)

def list_key_prefixes_hint() -> str:
    """Human hint for displaying newly created keys."""
    return "Copy the key exactly — no ambiguous characters used."

def generate_key(live: bool = True) -> str:
    """Return a new API key."""
    prefix = _PREFIX_LIVE if live else _PREFIX_TEST
    body = "".join(secrets.choice(_ALPHABET) for _ in range(40))
    return f"{prefix}{body}"


def key_prefix(key: str) -> str:
    """First 16 chars — safe to store and display."""
    return key[:16]


def hash_key(key: str) -> str:
    """SHA-256 hex digest of the key. What we store in the DB."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def verify_key(provided: str, stored_hash: str) -> bool:
    """Constant-time comparison of a provided key against a stored hash."""
    computed = hash_key(provided)
    return hmac.compare_digest(computed, stored_hash)