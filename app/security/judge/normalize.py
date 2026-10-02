"""
Deterministic tool-call normalization.

The normalizer converts several possible tool-call representations
into one canonical form.

Supported input shapes include:

    {"name": "...", "args": {...}}

and streaming accumulator output:

    {
        "name": "...",
        "arguments": {...}
    }

The normalizer must not depend on an LLM.
"""

from __future__ import annotations

import json
import re
from typing import Any


# ============================================================
# Detection patterns
# ============================================================


COMMENT_RE = re.compile(
    r"(/\*.*?\*/|--[^\n]*|#[^\n]*)",
    re.DOTALL,
)

B64_RE = re.compile(
    r"base64[:=]\s*([A-Za-z0-9+/=]{40,})",
    re.IGNORECASE,
)


# ============================================================
# Argument extraction
# ============================================================


def _extract_arguments(
    raw: dict[str, Any],
) -> dict[str, Any]:

    candidates = [
        raw.get("args"),
        raw.get("arguments"),
    ]

    function = raw.get(
        "function"
    )

    if isinstance(
        function,
        dict,
    ):
        candidates.append(
            function.get(
                "arguments"
            )
        )

    for candidate in candidates:

        if candidate is None:
            continue

        if isinstance(
            candidate,
            dict,
        ):
            return candidate

        if isinstance(
            candidate,
            str,
        ):

            try:

                parsed = json.loads(
                    candidate
                )

                if isinstance(
                    parsed,
                    dict,
                ):
                    return parsed

            except json.JSONDecodeError:
                continue

    return {}


# ============================================================
# Operation inference
# ============================================================


def _infer_operation(
    tool_name: str,
    args: dict[str, Any],
) -> tuple[str, str]:

    name = (
        tool_name
        or "unknown"
    ).strip().lower()

    sql = str(
        args.get(
            "query",
            ""
        )
        or ""
    ).strip()

    # --------------------------------------------------------
    # SQL operations
    # --------------------------------------------------------

    if sql:

        clean_sql = COMMENT_RE.sub(
            "",
            sql,
        ).strip().rstrip(";")

        sql_lower = clean_sql.lower()

        if sql_lower.startswith(
            (
                "select",
                "show",
                "describe",
                "explain",
            )
        ):
            return "read", clean_sql

        if sql_lower.startswith(
            (
                "drop",
                "truncate",
                "delete",
            )
        ):
            return "delete", clean_sql

        if sql_lower.startswith(
            (
                "insert",
                "update",
                "alter",
                "create",
            )
        ):
            return "write", clean_sql

        if sql_lower.startswith(
            (
                "exec",
                "execute",
                "call",
                "xp_",
            )
        ):
            return "execute", clean_sql

    # --------------------------------------------------------
    # Explicit external/network tools
    # --------------------------------------------------------

    external_markers = (
        "email.",
        "http.",
        "http_",
        "network.",
        "network_",
        "web.",
        "web_",
        "browser.",
        "browser_",
        "request.",
        "request_",
        "fetch.",
        "fetch_",
        "webhook.",
        "webhook_",
    )

    if name.startswith(
        external_markers
    ):
        return "external_call", sql

    # --------------------------------------------------------
    # Filesystem operations
    # --------------------------------------------------------

    if name.startswith(
        (
            "file.",
            "filesystem.",
        )
    ):

        if any(
            marker in name
            for marker in (
                "delete",
                "remove",
                "unlink",
            )
        ):
            return "delete", sql

        if any(
            marker in name
            for marker in (
                "write",
                "create",
                "save",
                "upload",
                "append",
            )
        ):
            return "write", sql

        if any(
            marker in name
            for marker in (
                "read",
                "get",
                "list",
                "stat",
            )
        ):
            return "read", sql

    # --------------------------------------------------------
    # Generic tool-name inference
    # --------------------------------------------------------

    if any(
        marker in name
        for marker in (
            "delete",
            "remove",
            "drop",
            "truncate",
        )
    ):
        return "delete", sql

    if any(
        marker in name
        for marker in (
            "execute",
            "exec",
            "run",
            "command",
            "shell",
        )
    ):
        return "execute", sql

    if any(
        marker in name
        for marker in (
            "write",
            "insert",
            "update",
            "create",
            "set",
            "save",
        )
    ):
        return "write", sql

    if any(
        marker in name
        for marker in (
            "read",
            "query",
            "get",
            "list",
            "show",
            "describe",
            "search",
        )
    ):
        return "read", sql

    return "unknown", sql


# ============================================================
# Main normalization function
# ============================================================


def normalize_tool_call(
    raw: dict[str, Any],
) -> dict[str, Any]:

    if not isinstance(
        raw,
        dict,
    ):
        raw = {}

    tool_name = str(
        raw.get(
            "name",
            "unknown",
        )
        or "unknown"
    )

    args = _extract_arguments(
        raw
    )

    operation, clean_sql = _infer_operation(
        tool_name,
        args,
    )

    serialized = json.dumps(
        raw,
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )

    query = str(
        args.get(
            "query",
            ""
        )
        or ""
    )

    contains_comment_bypass = bool(
        COMMENT_RE.search(
            query
        )
    )

    contains_compound_statement = (
        ";" in query.strip().rstrip(";")
        if query
        else False
    )

    contains_encoded_payload = bool(
        B64_RE.search(
            serialized
        )
    )

    target = (
        args.get("table")
        or args.get("host")
        or args.get("url")
        or args.get("path")
    )

    normalized_args: dict[str, Any] = dict(
        args
    )

    if clean_sql:
        normalized_args["sql"] = (
            clean_sql
        )

    return {
        "tool_name":
            tool_name,
        "op":
            operation,
        "target":
            (
                str(target)
                if target is not None
                else None
            ),
        "args_normalized":
            normalized_args,
        "contains_compound_statement":
            contains_compound_statement,
        "contains_comment_bypass":
            contains_comment_bypass,
        "contains_encoded_payload":
            contains_encoded_payload,
    }