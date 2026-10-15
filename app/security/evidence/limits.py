"""
Evidence API limits.

These limits are deliberately centralized so that every Evidence Fabric
operation has an explicit bounded execution envelope.

Phase 8:
    investigation
    forensic replay
    trace reconstruction
    compliance export

Later scale work in Phase 13 can tune these values without changing
the external contracts.
"""

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

MAX_GRAPH_DEPTH = 16
DEFAULT_GRAPH_DEPTH = 2

MAX_GRAPH_NODES = 250
DEFAULT_GRAPH_NODES = 100

MAX_GRAPH_EDGES = 500

MAX_VERIFY_EVENTS = 5000
MAX_VERIFY_NODES = 5000
MAX_VERIFY_EDGES = 10000

MAX_EXPORT_NODES = 5000
MAX_EXPORT_EDGES = 10000

MAX_TRACE_EVENTS = 5000
DEFAULT_TRACE_EVENTS = 250

MAX_REPLAY_EVENTS = 2000
DEFAULT_REPLAY_EVENTS = 250

MAX_TRACE_ID_LENGTH = 128
MAX_NODE_TYPE_LENGTH = 64
MAX_SOURCE_LENGTH = 64

MAX_CURSOR_LENGTH = 512

ZERO_SHA256 = "0" * 64

EVIDENCE_PACKAGE_SCHEMA_VERSION = "8.0"