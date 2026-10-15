"""Build-level tests for Phase 7 isolation policy contracts.

These tests are provided for the final AURAGENT verification pass. They are
not executed by the Phase 7 installer.
"""

from __future__ import annotations

import uuid

import pytest

from app.isolation.filesystem.mounts import FilesystemPolicyError, MountSpec
from app.isolation.network.egress import NetworkEgressPolicy, NetworkPolicyError
from app.isolation.policy import IsolationPolicy
from app.isolation.quotas import QuotaError, ResourceQuota
from app.isolation.runner import IsolationDeniedError, IsolationExecutionRequest, IsolationRunner
from app.security.context import SecurityContext
from app.security.delegation.model import AuthorityState


def _context(*capabilities: str) -> SecurityContext:
    return SecurityContext(
        tenant_id=uuid.uuid4(),
        agent_id=uuid.uuid4(),
        trace_id="phase7-test",
        capabilities=frozenset(capabilities),
        authority=AuthorityState.from_values(
            capabilities=capabilities,
            operations={"execute"},
            resources=(),
            data_scopes=(),
            network_scopes=(),
        ),
        policy_hash="test-policy",
    )


def test_default_policy_is_deny_network_and_non_root() -> None:
    policy = IsolationPolicy()
    assert policy.network.enabled is False
    assert policy.network.docker_network_mode == "none"
    assert policy.user != "0:0"


def test_external_network_requires_managed_proxy() -> None:
    with pytest.raises(NetworkPolicyError):
        NetworkEgressPolicy(enabled=True, allowed_domains=("example.com",))


def test_quota_ceiling_is_enforced() -> None:
    policy = IsolationPolicy(
        quota=ResourceQuota(cpu_cores=2.0, memory_mb=1024, timeout_seconds=10),
    )
    policy.quota.ensure_within(
        ResourceQuota(
            cpu_cores=4.0,
            memory_mb=4096,
            timeout_seconds=60,
            pids_limit=1024,
            max_output_bytes=2 * 1024 * 1024,
        )
    )


def test_host_mount_requires_allowed_root(tmp_path) -> None:
    mount = MountSpec(
        host_path=str(tmp_path),
        container_path="/workspace",
        read_only=True,
    )
    assert mount.validate([str(tmp_path)])


def test_missing_capability_denies_execution() -> None:
    runner = IsolationRunner()
    request = IsolationExecutionRequest(
        command=("python", "-c", "print('ok')"),
        policy=IsolationPolicy(),
    )
    with pytest.raises(IsolationDeniedError):
        runner._authorize_request(_context("memory:read"), request)


def test_policy_fingerprint_is_stable() -> None:
    first = IsolationPolicy().fingerprint()
    second = IsolationPolicy().fingerprint()
    assert first == second
    assert len(first) == 64
