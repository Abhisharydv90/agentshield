"""Memory integrity and boundary validation."""

from __future__ import annotations

import re

from app.security.identity.crypto import sha256_hex

MAX_MEMORY_CONTENT_BYTES = 512 * 1024
MAX_NAMESPACE_LENGTH = 200
MAX_KEY_LENGTH = 500

_SAFE_NAMESPACE = re.compile(r"^[A-Za-z0-9._:-]+$")


class MemoryValidationError(ValueError):
    pass


def validate_content(content: str) -> str:
    if not isinstance(content, str):
        raise MemoryValidationError("content must be text")
    encoded = content.encode("utf-8")
    if len(encoded) > MAX_MEMORY_CONTENT_BYTES:
        raise MemoryValidationError("memory content exceeds maximum size")
    if "\x00" in content:
        raise MemoryValidationError("memory content contains a NUL byte")
    return content


def validate_namespace(namespace: str) -> str:
    value = namespace.strip()
    if not value:
        raise MemoryValidationError("namespace is required")
    if len(value) > MAX_NAMESPACE_LENGTH:
        raise MemoryValidationError("namespace is too long")
    if not _SAFE_NAMESPACE.fullmatch(value):
        raise MemoryValidationError("namespace contains invalid characters")
    return value


def validate_key(key: str) -> str:
    value = key.strip()
    if not value:
        raise MemoryValidationError("key is required")
    if len(value) > MAX_KEY_LENGTH:
        raise MemoryValidationError("memory key is too long")
    if "\r" in value or "\n" in value:
        raise MemoryValidationError("memory key contains invalid characters")
    return value


def content_hash(content: str) -> str:
    return sha256_hex(content)


def verify_content_hash(content: str, expected: str) -> bool:
    return content_hash(content).lower() == expected.lower()
