"""Operator-controlled custom tool loader.

Dynamic import is intentionally restricted to an explicit allowlist. This is a
control-plane feature, not a mechanism for agents to execute arbitrary modules.
"""

from __future__ import annotations

import importlib
import re
from typing import Any


_TARGET_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$")


class CustomToolLoadError(ValueError):
    """Raised for unsafe or invalid custom tool targets."""


def load_handler(target: str, *, allowed_modules: set[str] | frozenset[str]) -> Any:
    value = str(target).strip()
    if not _TARGET_RE.fullmatch(value):
        raise CustomToolLoadError("custom handler must be module:attribute")

    module_name, attribute_name = value.split(":", 1)
    allowed = frozenset(str(item).strip() for item in allowed_modules if str(item).strip())
    if module_name not in allowed and not any(module_name.startswith(item + ".") for item in allowed):
        raise CustomToolLoadError("custom handler module is not allowlisted")

    if module_name.startswith("__") or ".." in module_name:
        raise CustomToolLoadError("unsafe module path")

    module = importlib.import_module(module_name)
    handler = getattr(module, attribute_name, None)
    if handler is None or not callable(handler):
        raise CustomToolLoadError("custom handler is not callable")
    return handler
