"""P0 regression tests for tenant/agent ownership of isolation executions."""

from __future__ import annotations

import uuid

import pytest

from app.isolation.policy import IsolationPolicy
from app.isolation.runner import (
    IsolationExecutionResult,
    IsolationRunner,
)
from app.security.context import SecurityContext
from app.security.delegation.model import AuthorityState


def _context(
    tenant_id: uuid.UUID | None = None,
    agent_id: uuid.UUID | None = None,
) -> SecurityContext:
    tenant_id = tenant_id or uuid.uuid4()
    agent_id = agent_id or uuid.uuid4()
    capabilities = frozenset({"execute"})
    return SecurityContext(
        tenant_id=tenant_id,
        agent_id=agent_id,
        trace_id="test-trace",
        capabilities=capabilities,
        authority=AuthorityState.from_values(
            capabilities=capabilities,
            operations={"execute"},
        ),
        policy_hash="test-policy",
    )


def _result(execution_id: str) -> IsolationExecutionResult:
    return IsolationExecutionResult(
        execution_id=execution_id,
        status="completed",
        backend="docker",
        strong_isolation=True,
        exit_code=0,
        timed_out=False,
        duration_ms=1,
        stdout="ok",
        stderr="",
        policy_hash="policy",
        trace_id="trace",
    )


def test_get_requires_exact_tenant_and_agent_owner() -> None:
    import asyncio

    async def scenario() -> None:
        runner = IsolationRunner()
        execution_id = str(uuid.uuid4())
        owner = _context()
        attacker = _context()

        runner._history[execution_id] = _result(execution_id)
        runner._ownership[execution_id] = (
            owner.tenant_id,
            owner.agent_id,
        )

        assert await runner.get(execution_id, context=owner) is not None
        assert await runner.get(execution_id, context=attacker) is None

        same_tenant_other_agent = _context(
            tenant_id=owner.tenant_id,
        )
        assert await runner.get(execution_id, context=same_tenant_other_agent) is None

        same_agent_other_tenant = _context(
            agent_id=owner.agent_id,
        )
        assert await runner.get(execution_id, context=same_agent_other_tenant) is None

    asyncio.run(scenario())


@pytest.mark.asyncio
async def test_stop_requires_exact_owner_and_uses_recorded_backend() -> None:
    class FakeLifecycle:
        def __init__(self) -> None:
            self.calls = []

        def stop(self, *, backend_name: str, execution_id: str) -> None:
            self.calls.append((backend_name, execution_id))

    lifecycle = FakeLifecycle()
    runner = IsolationRunner(lifecycle=lifecycle)
    execution_id = str(uuid.uuid4())
    owner = _context()
    attacker = _context()

    runner._active[execution_id] = (
        owner.tenant_id,
        owner.agent_id,
        "docker",
    )

    assert not await runner.stop(execution_id, context=attacker)
    assert lifecycle.calls == []

    assert await runner.stop(execution_id, context=owner)
    assert lifecycle.calls == [("docker", execution_id)]


@pytest.mark.asyncio
async def test_missing_owner_metadata_fails_closed() -> None:
    runner = IsolationRunner()
    execution_id = str(uuid.uuid4())
    owner = _context()

    runner._history[execution_id] = _result(execution_id)

    assert await runner.get(execution_id, context=owner) is None


@pytest.mark.asyncio
async def test_run_binds_execution_to_context() -> None:
    class FakeBackend:
        name = "docker"
        strong_isolation = True
        supports_managed_egress = True

        def available(self) -> bool:
            return True

    class FakeLifecycle:
        def __init__(self) -> None:
            self.backends = {"docker": FakeBackend()}

        def run(self, *, backend_name, execution_id, config):
            class Raw:
                exit_code = 0
                timed_out = False
                stdout = "ok"
                stderr = ""
                duration_ms = 1

            return Raw()

        def stop(self, *, backend_name, execution_id):
            pass

    runner = IsolationRunner(lifecycle=FakeLifecycle())
    owner = _context()

    request = __import__(
        "app.isolation.runner",
        fromlist=["IsolationExecutionRequest"],
    ).IsolationExecutionRequest(
        command=("python", "-c", "print('ok')"),
        policy=IsolationPolicy(),
    )

    result = await runner.run(owner, request)

    assert runner._ownership[result.execution_id] == (
        owner.tenant_id,
        owner.agent_id,
    )
    assert await runner.get(result.execution_id, context=owner) is not None
