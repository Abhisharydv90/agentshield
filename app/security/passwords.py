"""
Password hashing using Argon2id.

Argon2id is the current OWASP recommendation — memory-hard, GPU-resistant,
and resistant to side-channel attacks. We use the `argon2-cffi` library.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError


_hasher = PasswordHasher(
    time_cost=2,        # iterations
    memory_cost=65536,  # 64 MB
    parallelism=1,
    hash_len=32,
    salt_len=16,
)


def hash_password(password: str) -> str:
    """Return an Argon2id hash. Safe to store."""
    return _hasher.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a plaintext password against a stored hash."""
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True if the stored hash was made with weaker parameters."""
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except (VerificationError, InvalidHashError):
        return False