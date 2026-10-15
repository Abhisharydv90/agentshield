"""
AURAGENT Gateway routing package.
"""

from app.gateway.routing.a2a import (
    A2ARoute,
    A2ARouteError,
    A2ARouter,
    a2a_router,
)
from app.gateway.routing.agent import (
    AgentRouteError,
    AgentRouter,
)
from app.gateway.routing.mcp import (
    MCPRoute,
    MCPRouteError,
    MCPRouter,
    mcp_router,
)
from app.gateway.routing.model import (
    ModelRoute,
    ModelRouteError,
    ModelRouteRegistry,
    get_model_router,
)

__all__ = [
    "ModelRoute",
    "ModelRouteError",
    "ModelRouteRegistry",
    "get_model_router",
    "AgentRouter",
    "AgentRouteError",
    "MCPRoute",
    "MCPRouteError",
    "MCPRouter",
    "mcp_router",
    "A2ARoute",
    "A2ARouteError",
    "A2ARouter",
    "a2a_router",
]