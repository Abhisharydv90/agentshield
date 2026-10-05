"""
Shared evidence query and investigation limits.

These limits are intentionally centralized so the Evidence Graph,
investigation API, verification API, export path, and dashboard all
operate under one bounded contract.

This is also the scaling boundary for 7J:
- keyset pagination instead of OFFSET pagination
- bounded graph traversal
- bounded compliance export
- bounded verification work
"""

from __future__ import annotations


DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

MAX_GRAPH_DEPTH = 16
DEFAULT_GRAPH_DEPTH = 2

MAX_GRAPH_NODES = 250
DEFAULT_GRAPH_NODES = 100

MAX_GRAPH_EDGES = 500

MAX_VERIFY_EVENTS = 5_000
MAX_VERIFY_NODES = 5_000
MAX_VERIFY_EDGES = 10_000

MAX_EXPORT_NODES = 5_000
MAX_EXPORT_EDGES = 10_000

MAX_TRACE_ID_LENGTH = 128
MAX_NODE_TYPE_LENGTH = 64
MAX_SOURCE_LENGTH = 64
MAX_CURSOR_LENGTH = 512

ZERO_SHA256 = "0" * 64