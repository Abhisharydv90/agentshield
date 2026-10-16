"""P3 runtime control-plane authorization regression tests."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from starlette.requests import Request

from app.api import runtime
from app.api import workflows


def _request(
    tenant_id: uuid.UUID,
    agent_id: uuid.UUID,
    scopes: list[str] | None = None,
) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/runtime",
        "headers": [],
        "state": {},
    }
    request = Request(scope)
    request.state.tenant = SimpleNamespace(
        tenant_id=tenant_id,
        status="active",
    )
    request.state.agent = SimpleNamespace(
        agent_id=agent_id,
        status="active",
        scopes=scopes if scopes is not None else ["agent:invoke"],
    )
    return request


def _record(
    tenant_id: uuid.UUID,
    agent_id: uuid.UUID,
    task_id: uuid.UUID | None = None,
):
    task_id = task_id or uuid.uuid4()
    spec = SimpleNamespace(
        kind="test",
        priority=0,
        max_attempts=3,
        timeout_seconds=30,
        payload_hash="a" * 64,
    )
    return SimpleNamespace(
        task_id=task_id,
        tenant_id=tenant_id,
        agent_id=agent_id,
        trace_id="trace-test",
        spec=spec,
        status=SimpleNamespace(value="queued"),
        attempt_count=0,
        result_hash=None,
        last_error_code=None,
    )


@pytest.mark.asyncio
async def test_get_task_denies_same_tenant_other_agent(monkeypatch):
    tenant_id = uuid.uuid4()
    owner_agent_id = uuid.uuid4()
    caller_agent_id = uuid.uuid4()
    task_id = uuid.uuid4()
    record = _record(tenant_id, owner_agent_id, task_id)

    class Store:
        async def get_task(self, tenant_id_arg, task_id_arg):
            assert tenant_id_arg == tenant_id
            assert task_id_arg == task_id
            return record

    class Engine:
        store = Store()

    async def fake_engine():
        return Engine()

    monkeypatch.setattr(runtime, "get_runtime_engine", fake_engine)

    with pytest.raises(runtime.HTTPException) as exc_info:
        await runtime.get_task(
            _request(tenant_id, caller_agent_id),
            task_id,
        )

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "runtime_task_not_found"


@pytest.mark.asyncio
async def test_cancel_task_denies_other_agent_before_scheduler(monkeypatch):
    tenant_id = uuid.uuid4()
    owner_agent_id = uuid.uuid4()
    caller_agent_id = uuid.uuid4()
    task_id = uuid.uuid4()
    record = _record(tenant_id, owner_agent_id, task_id)

    class Store:
        async def get_task(self, tenant_id_arg, task_id_arg):
            return record

    class Engine:
        store = Store()
        cancel_called = False

        async def cancel_task(self, **kwargs):
            self.cancel_called = True
            return True

    engine = Engine()

    async def fake_engine():
        return engine

    monkeypatch.setattr(runtime, "get_runtime_engine", fake_engine)

    with pytest.raises(runtime.HTTPException) as exc_info:
        await runtime.cancel_task(
            _request(tenant_id, caller_agent_id),
            task_id,
        )

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "runtime_task_not_found"
    assert engine.cancel_called is False


@pytest.mark.asyncio
async def test_close_session_denies_other_agent_before_close(monkeypatch):
    tenant_id = uuid.uuid4()
    owner_agent_id = uuid.uuid4()
    caller_agent_id = uuid.uuid4()
    session_id = uuid.uuid4()

    class Sessions:
        close_called = False

        async def get(self, *, tenant_id, session_id):
            return SimpleNamespace(
                tenant_id=tenant_id,
                agent_id=owner_agent_id,
            )

        async def close(self, **kwargs):
            self.close_called = True

    class Engine:
        sessions = Sessions()

    engine = Engine()

    async def fake_engine():
        return engine

    monkeypatch.setattr(runtime, "get_runtime_engine", fake_engine)

    with pytest.raises(runtime.HTTPException) as exc_info:
        await runtime.close_session(
            _request(tenant_id, caller_agent_id),
            session_id,
        )

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "runtime_session_not_found"
    assert engine.sessions.close_called is False


@pytest.mark.asyncio
async def test_close_session_allows_exact_agent_owner(monkeypatch):
    tenant_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    session_id = uuid.uuid4()

    class Sessions:
        close_called = False

        async def get(self, *, tenant_id, session_id):
            return {
                "tenant_id": tenant_id,
                "agent_id": agent_id,
            }

        async def close(self, **kwargs):
            self.close_called = True

    sessions = Sessions()

    class Engine:
        pass

    engine = Engine()
    engine.sessions = sessions

    async def fake_engine():
        return engine

    monkeypatch.setattr(runtime, "get_runtime_engine", fake_engine)

    result = await runtime.close_session(
        _request(tenant_id, agent_id),
        session_id,
    )

    assert result == {
        "status": "closed",
        "session_id": str(session_id),
    }
    assert sessions.close_called is True


@pytest.mark.asyncio
async def test_runtime_and_workflow_require_invoke_capability(monkeypatch):
    tenant_id = uuid.uuid4()
    agent_id = uuid.uuid4()

    class Engine:
        pass

    async def fake_engine():
        raise AssertionError("runtime engine must not be reached")

    monkeypatch.setattr(runtime, "get_runtime_engine", fake_engine)
    monkeypatch.setattr(workflows, "get_runtime_engine", fake_engine)

    request = _request(tenant_id, agent_id, scopes=["tool:read"])

    with pytest.raises(runtime.HTTPException) as runtime_exc:
        await runtime.create_session(request)

    assert runtime_exc.value.status_code == 403
    assert runtime_exc.value.detail == {
        "error": "capability_required",
        "capability": "agent:invoke",
    }

    body = workflows.WorkflowSubmitRequest(
        name="test-workflow",
        version="1",
        steps=[
            workflows.WorkflowStepRequest(
                key="step-1",
                task_kind="test",
                agent_id=agent_id,
            )
        ],
    )

    with pytest.raises(workflows.HTTPException) as workflow_exc:
        await workflows.submit_workflow(request, body)

    assert workflow_exc.value.status_code == 403
    assert workflow_exc.value.detail == {
        "error": "capability_required",
        "capability": "agent:invoke",
    }


@pytest.mark.asyncio
async def test_runtime_task_submission_hides_unexpected_exception(monkeypatch):
    tenant_id = uuid.uuid4()
    agent_id = uuid.uuid4()

    class Engine:
        async def submit_task(self, spec):
            raise RuntimeError("secret database connection details")

    async def fake_engine():
        return Engine()

    monkeypatch.setattr(runtime, "get_runtime_engine", fake_engine)

    with pytest.raises(runtime.HTTPException) as exc_info:
        await runtime.submit_task(
            _request(tenant_id, agent_id),
            runtime.TaskSubmitRequest(kind="test"),
        )

    assert exc_info.value.status_code == 500
    assert exc_info.value.detail == "runtime_task_submission_failed"


@pytest.mark.asyncio
async def test_workflow_submission_hides_unexpected_exception(monkeypatch):
    tenant_id = uuid.uuid4()
    agent_id = uuid.uuid4()

    class Workflows:
        async def submit(self, **kwargs):
            raise RuntimeError("secret scheduler/database details")

    class Engine:
        workflows = Workflows()

    async def fake_engine():
        return Engine()

    monkeypatch.setattr(workflows, "get_runtime_engine", fake_engine)

    body = workflows.WorkflowSubmitRequest(
        name="test-workflow",
        version="1",
        steps=[
            workflows.WorkflowStepRequest(
                key="step-1",
                task_kind="test",
                agent_id=agent_id,
            )
        ],
    )

    with pytest.raises(workflows.HTTPException) as exc_info:
        await workflows.submit_workflow(
            _request(tenant_id, agent_id),
            body,
        )

    assert exc_info.value.status_code == 500
    assert exc_info.value.detail == "workflow_submission_failed"
