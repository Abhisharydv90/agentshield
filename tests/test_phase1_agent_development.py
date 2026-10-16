"""Phase 1 agent development unit coverage."""

from __future__ import annotations

import json
import uuid

import pytest
from fastapi import HTTPException

from app.db.models import Base
from app.development.builder import build_manifest
from app.development.lifecycle import validate_transition
from app.development.models import AgentDeployment, AgentMember, AgentTemplate, AgentVersion
from app.development.templates import content_hash, normalize_version
from app.api.agents import AgentCreateRequest, TemplateCreateRequest, VersionCreateRequest
from app.security.capabilities import Capability


def test_phase1_tables_are_registered_with_base_metadata():
    names = Base.metadata.tables.keys()
    assert "agent_versions" in names
    assert "agent_templates" in names
    assert "agent_deployments" in names
    assert "agent_members" in names


def test_agent_version_has_tenant_agent_version_uniqueness():
    table = AgentVersion.__table__
    names = {c.name for c in table.constraints if getattr(c, "name", None)}
    assert "uq_agent_versions_tenant_agent_version" in names


def test_builder_creates_bounded_manifest():
    manifest = build_manifest(
        runtime="python",
        entrypoint="agent.main:run",
        model="openai/gpt-5",
        tools=["search", "calendar"],
        environment={"LOG_LEVEL": "INFO"},
    )
    assert manifest["runtime"] == "python"
    assert manifest["entrypoint"] == "agent.main:run"
    assert manifest["model"] == "openai/gpt-5"
    assert manifest["tools"] == ["search", "calendar"]


def test_builder_rejects_missing_runtime():
    with pytest.raises(ValueError, match="agent_runtime_required"):
        build_manifest(runtime="", entrypoint="main:run")


def test_version_validation_is_semver_like():
    assert normalize_version("1.2.3") == "1.2.3"
    assert normalize_version("2.0.0-beta.1") == "2.0.0-beta.1"
    with pytest.raises(ValueError, match="invalid_agent_version"):
        normalize_version("latest")


def test_content_hash_is_deterministic_and_sensitive():
    kwargs = {
        "name": "agent",
        "description": "test",
        "version": "1.0.0",
        "capabilities": [Capability.AGENT_INVOKE.value],
        "manifest": {"runtime": "python"},
    }
    first = content_hash(**kwargs)
    second = content_hash(**kwargs)
    changed = content_hash(**{**kwargs, "manifest": {"runtime": "node"}})
    assert first == second
    assert first != changed
    assert len(first) == 64


@pytest.mark.parametrize(
    ("current", "target"),
    [
        ("active", "suspended"),
        ("active", "revoked"),
        ("suspended", "active"),
        ("suspended", "revoked"),
    ],
)
def test_valid_lifecycle_transitions(current: str, target: str):
    validate_transition(current, target)


def test_revoked_agent_is_terminal():
    with pytest.raises(HTTPException, match="invalid_agent_lifecycle_transition"):
        validate_transition("revoked", "active")


def test_unknown_agent_lifecycle_status_is_rejected():
    with pytest.raises(HTTPException, match="invalid_agent_status"):
        validate_transition("active", "bogus")


def test_agent_create_requires_invoke_capability():
    with pytest.raises(ValueError, match="agent_invoke_capability_required"):
        AgentCreateRequest(
            name="demo",
            capabilities=["tool:read"],
            manifest={},
        )


def test_agent_create_deduplicates_and_normalizes_capabilities():
    req = AgentCreateRequest(
        name="demo",
        capabilities=[
            " agent:invoke ",
            "tool:read",
            "tool:read",
        ],
    )
    assert req.capabilities == [
        Capability.AGENT_INVOKE.value,
        Capability.TOOL_READ.value,
    ]


def test_version_request_rejects_unknown_capability():
    with pytest.raises(ValueError):
        VersionCreateRequest(
            version="1.1.0",
            capabilities=["agent:invoke", "tool:not-real"],
            manifest={},
        )


def test_template_create_requires_bounded_json():
    huge = {"payload": "x" * (256 * 1024)}
    with pytest.raises(ValueError, match="template_manifest_too_large"):
        TemplateCreateRequest(
            name="huge",
            capabilities=[Capability.AGENT_INVOKE.value],
            manifest=huge,
        )


def test_phase1_json_is_compact_and_serializable():
    data = {"a": [1, 2, 3], "b": True}
    assert len(
        json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ) < 1024
