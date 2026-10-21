"""Phase 2 runtime orchestration contract tests.

These tests deliberately use InMemoryRuntimeStore so core lifecycle and
scheduler behavior can be exercised without a live database.
"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import replace

import pytest

from app.runtime.durable import InMemoryRuntimeStore
from app.runtime.lifecycle import (
    InvalidTaskTransition,
    LifecycleManager,
)
from app.runtime.recovery import RecoveryManager
from app.runtime.scheduler.scheduler import (
    SchedulerStopped,
    TaskScheduler,
)
from app.runtime.tasks import (
    TaskRecord,
    TaskSpec,
    TaskStatus,
    canonical_hash,
)
from app.runtime.workflows.engine import (
    WorkflowEngine,
    WorkflowSpec,
    WorkflowStepSpec,
    WorkflowValidationError,
)


def make_spec(**overrides) -> TaskSpec:
    values = {
        "tenant_id": uuid.uuid4(),
        "agent_id": uuid.uuid4(),
        "kind": "test.echo",
        "payload": {"message": "hello"},
        "timeout_seconds": 2,
        "max_attempts": 2,
    }
    values.update(overrides)
    return TaskSpec(**values)


async def wait_for_status(
    store: InMemoryRuntimeStore,
    tenant_id: uuid.UUID,
    task_id: uuid.UUID,
    expected: TaskStatus,
    *,
    timeout: float = 2.0,
) -> TaskRecord:
    async def poll() -> TaskRecord:
        while True:
            record = await store.get_task(tenant_id, task_id)
            if record is not None and record.status == expected:
                return record
            await asyncio.sleep(0.005)

    return await asyncio.wait_for(poll(), timeout=timeout)


def test_task_spec_hash_is_deterministic_for_mapping_key_order():
    assert canonical_hash({"a": 1, "b": 2}) == canonical_hash(
        {"b": 2, "a": 1}
    )
    assert make_spec(payload={"a": 1, "b": 2}).payload_hash == make_spec(
        payload={"b": 2, "a": 1}
    ).payload_hash


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("kind", " ", "task_kind_required"),
        ("kind", "x" * 161, "task_kind_too_long"),
        ("priority", 100001, "priority_out_of_range"),
        ("timeout_seconds", 0, "timeout_seconds_out_of_range"),
        ("max_attempts", 0, "max_attempts_out_of_range"),
        ("trace_id", "x" * 129, "trace_id_too_long"),
    ],
)
def test_task_spec_rejects_out_of_range_contract_values(field, value, message):
    with pytest.raises(ValueError, match=message):
        make_spec(**{field: value})


def test_lifecycle_rejects_terminal_state_reopening():
    record = TaskRecord(spec=make_spec())
    LifecycleManager.queue(record)
    LifecycleManager.start(record)
    LifecycleManager.succeed(record, {"ok": True})

    assert record.status is TaskStatus.SUCCEEDED
    assert record.result_hash == canonical_hash({"ok": True})
    assert record.finished_at is not None

    with pytest.raises(InvalidTaskTransition):
        LifecycleManager.transition(record, TaskStatus.RUNNING)


def test_lifecycle_counts_attempts_and_records_failure():
    record = TaskRecord(spec=make_spec(max_attempts=1))
    LifecycleManager.queue(record)
    LifecycleManager.start(record)
    assert record.attempt_count == 1

    LifecycleManager.fail(record, "executor_error")
    assert record.status is TaskStatus.FAILED
    assert record.last_error_code == "executor_error"
    assert record.finished_at is not None


def test_recovery_retry_delay_is_exponential_and_bounded():
    manager = RecoveryManager(
        InMemoryRuntimeStore(),
        base_delay_seconds=2,
        max_delay_seconds=5,
    )
    assert manager.retry_delay(1) == 2
    assert manager.retry_delay(2) == 4
    assert manager.retry_delay(3) == 5
    assert manager.retry_delay(0) == 2


@pytest.mark.asyncio
async def test_store_scopes_task_reads_to_tenant():
    store = InMemoryRuntimeStore()
    spec = make_spec()
    await store.create_task(spec)

    assert await store.get_task(spec.tenant_id, spec.task_id) is not None
    assert await store.get_task(uuid.uuid4(), spec.task_id) is None


@pytest.mark.asyncio
async def test_scheduler_accepts_idempotent_replay_with_same_dependencies():
    store = InMemoryRuntimeStore()
    tenant_id = uuid.uuid4()
    parent = make_spec(tenant_id=tenant_id, kind="parent")
    await store.create_task(parent)

    scheduler = TaskScheduler(
        store, executor=lambda task: task.spec.kind,
        poll_interval_seconds=0.005,
    )
    original = make_spec(
        tenant_id=tenant_id,
        idempotency_key="replay-same",
        kind="child",
        payload={"x": 1},
    )
    replay = replace(original, task_id=uuid.uuid4())

    await scheduler.start()
    try:
        first = await scheduler.submit(
            original, dependencies=[parent.task_id]
        )
        second = await scheduler.submit(
            replay, dependencies=[parent.task_id]
        )
        assert second.task_id == first.task_id
        assert await store.list_task_dependencies(tenant_id, first.task_id) == {
            parent.task_id
        }
    finally:
        await scheduler.stop()


@pytest.mark.asyncio
async def test_scheduler_rejects_idempotency_replay_with_different_dependencies():
    store = InMemoryRuntimeStore()
    tenant_id = uuid.uuid4()
    parent_a = make_spec(tenant_id=tenant_id, kind="parent.a")
    parent_b = make_spec(tenant_id=tenant_id, kind="parent.b")
    await store.create_task(parent_a)
    await store.create_task(parent_b)

    scheduler = TaskScheduler(
        store, executor=lambda task: task.spec.kind,
        poll_interval_seconds=0.005,
    )
    first_spec = make_spec(
        tenant_id=tenant_id,
        idempotency_key="same-request",
        kind="child",
        payload={"x": 1},
    )
    # Same logical request and identity; only the generated task ID differs.
    replay_spec = replace(
        first_spec,
        task_id=uuid.uuid4(),
    )

    await scheduler.start()
    try:
        first = await scheduler.submit(
            first_spec, dependencies=[parent_a.task_id]
        )
        with pytest.raises(ValueError, match="idempotency_dependency_conflict"):
            await scheduler.submit(
                replay_spec, dependencies=[parent_b.task_id]
            )

        persisted = await store.get_task(tenant_id, first.task_id)
        assert persisted is not None
        assert persisted.last_error_code != "submission_failed"
        assert await store.list_task_dependencies(tenant_id, first.task_id) == {
            parent_a.task_id
        }
    finally:
        await scheduler.stop()


@pytest.mark.asyncio
async def test_store_rejects_idempotency_key_reuse_for_different_payload():
    store = InMemoryRuntimeStore()
    original = make_spec(
        idempotency_key="request-123",
        payload={"operation": "read"},
    )
    await store.create_task(original)

    conflicting = make_spec(
        tenant_id=original.tenant_id,
        agent_id=original.agent_id,
        idempotency_key="request-123",
        payload={"operation": "delete"},
    )
    with pytest.raises(ValueError, match="idempotency_key_conflict"):
        await store.create_task(conflicting)


@pytest.mark.asyncio
async def test_store_returns_existing_task_for_same_idempotent_request():
    store = InMemoryRuntimeStore()
    original = make_spec(
        idempotency_key="request-456",
        payload={"operation": "read"},
    )
    first = await store.create_task(original)
    replay = make_spec(
        tenant_id=original.tenant_id,
        agent_id=original.agent_id,
        idempotency_key="request-456",
        payload={"operation": "read"},
    )

    second = await store.create_task(replay)
    assert second.task_id == first.task_id


@pytest.mark.asyncio
async def test_store_rejects_cross_tenant_dependency():
    store = InMemoryRuntimeStore()
    parent = make_spec()
    child = make_spec(tenant_id=parent.tenant_id)

    await store.create_task(parent)
    await store.create_task(child)

    with pytest.raises(PermissionError, match="cross_tenant_task_dependency"):
        await store.add_dependency(
            uuid.uuid4(), child.task_id, parent.task_id
        )


@pytest.mark.asyncio
async def test_scheduler_requires_start_before_submission():
    scheduler = TaskScheduler(
        InMemoryRuntimeStore(),
        executor=lambda task: task.spec.payload,
        poll_interval_seconds=0.01,
    )
    with pytest.raises(SchedulerStopped, match="scheduler_not_running"):
        await scheduler.submit(make_spec())


@pytest.mark.asyncio
async def test_scheduler_executes_task_and_persists_result_hash():
    store = InMemoryRuntimeStore()
    scheduler = TaskScheduler(
        store,
        executor=lambda task: {"echo": task.spec.payload},
        poll_interval_seconds=0.005,
    )
    spec = make_spec()
    await scheduler.start()
    try:
        await scheduler.submit(spec)
        record = await wait_for_status(
            store, spec.tenant_id, spec.task_id, TaskStatus.SUCCEEDED
        )
        assert record.result_hash == canonical_hash({"echo": spec.payload})
        assert record.attempt_count == 1
    finally:
        await scheduler.stop()


@pytest.mark.asyncio
async def test_scheduler_retries_transient_executor_error_then_succeeds():
    store = InMemoryRuntimeStore()
    calls = 0

    async def executor(task):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("transient")
        return "done"

    scheduler = TaskScheduler(
        store, executor=executor, poll_interval_seconds=0.005
    )
    scheduler.recovery.base_delay_seconds = 0
    spec = make_spec(max_attempts=2)
    await scheduler.start()
    try:
        await scheduler.submit(spec)
        record = await wait_for_status(
            store, spec.tenant_id, spec.task_id, TaskStatus.SUCCEEDED
        )
        assert calls == 2
        assert record.attempt_count == 2
        assert record.result_hash == canonical_hash("done")
    finally:
        await scheduler.stop()


@pytest.mark.asyncio
async def test_scheduler_marks_task_failed_after_attempt_limit():
    store = InMemoryRuntimeStore()

    async def executor(task):
        raise ValueError("no")

    scheduler = TaskScheduler(
        store, executor=executor, poll_interval_seconds=0.005
    )
    spec = make_spec(max_attempts=1)
    await scheduler.start()
    try:
        await scheduler.submit(spec)
        record = await wait_for_status(
            store, spec.tenant_id, spec.task_id, TaskStatus.FAILED
        )
        assert record.attempt_count == 1
        assert record.last_error_code == "valueerror"
    finally:
        await scheduler.stop()


@pytest.mark.asyncio
async def test_scheduler_enforces_task_timeout():
    store = InMemoryRuntimeStore()

    async def executor(task):
        await asyncio.sleep(5)

    scheduler = TaskScheduler(
        store, executor=executor, poll_interval_seconds=0.005
    )
    spec = make_spec(timeout_seconds=1, max_attempts=1)
    await scheduler.start()
    try:
        await scheduler.submit(spec)
        record = await wait_for_status(
            store, spec.tenant_id, spec.task_id, TaskStatus.FAILED,
            timeout=2.5,
        )
        assert record.last_error_code == "task_timeout"
    finally:
        await scheduler.stop()


@pytest.mark.asyncio
async def test_scheduler_honors_task_dependencies():
    store = InMemoryRuntimeStore()
    started: list[str] = []
    release_parent = asyncio.Event()

    async def executor(task):
        started.append(task.spec.kind)
        if task.spec.kind == "parent":
            await release_parent.wait()
        return task.spec.kind

    scheduler = TaskScheduler(
        store, executor=executor, poll_interval_seconds=0.005
    )
    tenant_id = uuid.uuid4()
    parent = make_spec(tenant_id=tenant_id, kind="parent")
    child = make_spec(tenant_id=tenant_id, kind="child")
    await scheduler.start()
    try:
        await scheduler.submit(parent)
        await scheduler.submit(child, dependencies=[parent.task_id])
        await asyncio.sleep(0.05)
        assert "parent" in started
        assert "child" not in started

        release_parent.set()
        await wait_for_status(
            store, tenant_id, parent.task_id, TaskStatus.SUCCEEDED
        )
        await wait_for_status(
            store, tenant_id, child.task_id, TaskStatus.SUCCEEDED
        )
        assert started.index("parent") < started.index("child")
    finally:
        release_parent.set()
        await scheduler.stop()


@pytest.mark.asyncio
async def test_scheduler_blocks_child_after_parent_failure():
    store = InMemoryRuntimeStore()
    scheduler = TaskScheduler(
        store, executor=lambda task: task.spec.kind, poll_interval_seconds=0.005
    )
    tenant_id = uuid.uuid4()
    parent = make_spec(tenant_id=tenant_id, kind="parent", max_attempts=1)
    child = make_spec(tenant_id=tenant_id, kind="child")
    async def executor(task):
        if task.spec.kind == "parent":
            raise RuntimeError("parent failed")
        return "child should never execute"
    scheduler.executor = executor
    await scheduler.start()
    try:
        await scheduler.submit(parent)
        await scheduler.submit(child, dependencies=[parent.task_id])
        await wait_for_status(store, tenant_id, parent.task_id, TaskStatus.FAILED)
        blocked = await wait_for_status(
            store, tenant_id, child.task_id, TaskStatus.BLOCKED
        )
        assert blocked.last_error_code == "dependency_failed"
    finally:
        await scheduler.stop()


@pytest.mark.asyncio
async def test_scheduler_blocks_child_after_parent_cancellation():
    store = InMemoryRuntimeStore()
    started = asyncio.Event()
    release = asyncio.Event()

    async def executor(task):
        if task.spec.kind == "parent":
            started.set()
            await release.wait()
        return task.spec.kind

    scheduler = TaskScheduler(
        store, executor=executor, poll_interval_seconds=0.005
    )
    tenant_id = uuid.uuid4()
    parent = make_spec(tenant_id=tenant_id, kind="parent")
    child = make_spec(tenant_id=tenant_id, kind="child")
    await scheduler.start()
    try:
        await scheduler.submit(parent)
        await scheduler.submit(child, dependencies=[parent.task_id])
        await asyncio.wait_for(started.wait(), timeout=1)
        assert await scheduler.cancel(tenant_id=tenant_id, task_id=parent.task_id)
        blocked = await wait_for_status(
            store, tenant_id, child.task_id, TaskStatus.BLOCKED
        )
        assert blocked.last_error_code == "dependency_failed"
    finally:
        release.set()
        await scheduler.stop()


@pytest.mark.asyncio
async def test_scheduler_blocks_partial_submission_when_dependency_is_missing():
    store = InMemoryRuntimeStore()
    scheduler = TaskScheduler(
        store, executor=lambda task: "must not execute",
        poll_interval_seconds=0.005,
    )
    spec = make_spec()
    missing_parent_id = uuid.uuid4()

    await scheduler.start()
    try:
        with pytest.raises(KeyError, match="task_dependency_not_found"):
            await scheduler.submit(spec, dependencies=[missing_parent_id])

        record = await wait_for_status(
            store, spec.tenant_id, spec.task_id, TaskStatus.BLOCKED
        )
        assert record.last_error_code == "submission_failed"
    finally:
        await scheduler.stop()


@pytest.mark.asyncio
async def test_scheduler_propagates_failure_through_dependency_chain():
    store = InMemoryRuntimeStore()

    async def executor(task):
        if task.spec.kind == "root":
            raise RuntimeError("root failed")
        return task.spec.kind

    scheduler = TaskScheduler(
        store, executor=executor, poll_interval_seconds=0.005
    )
    tenant_id = uuid.uuid4()
    root = make_spec(tenant_id=tenant_id, kind="root", max_attempts=1)
    middle = make_spec(tenant_id=tenant_id, kind="middle")
    leaf = make_spec(tenant_id=tenant_id, kind="leaf")

    await scheduler.start()
    try:
        await scheduler.submit(root)
        await scheduler.submit(middle, dependencies=[root.task_id])
        await scheduler.submit(leaf, dependencies=[middle.task_id])

        await wait_for_status(store, tenant_id, root.task_id, TaskStatus.FAILED)
        middle_record = await wait_for_status(
            store, tenant_id, middle.task_id, TaskStatus.BLOCKED
        )
        leaf_record = await wait_for_status(
            store, tenant_id, leaf.task_id, TaskStatus.BLOCKED
        )

        assert middle_record.last_error_code == "dependency_failed"
        assert leaf_record.last_error_code == "dependency_failed"
    finally:
        await scheduler.stop()


@pytest.mark.asyncio
async def test_scheduler_shutdown_retries_interrupted_running_task():
    store = InMemoryRuntimeStore()
    started = asyncio.Event()

    async def executor(task):
        started.set()
        await asyncio.Event().wait()

    scheduler = TaskScheduler(
        store, executor=executor, poll_interval_seconds=0.005
    )
    spec = make_spec(max_attempts=3)
    await scheduler.start()
    await scheduler.submit(spec)
    await asyncio.wait_for(started.wait(), timeout=1)

    await scheduler.stop()

    record = await store.get_task(spec.tenant_id, spec.task_id)
    assert record is not None
    assert record.status == TaskStatus.RETRYING
    assert record.last_error_code == "scheduler_shutdown"
    assert record.attempt_count == 1


async def test_scheduler_cancels_running_task():
    store = InMemoryRuntimeStore()
    started = asyncio.Event()

    async def executor(task):
        started.set()
        await asyncio.Event().wait()

    scheduler = TaskScheduler(
        store, executor=executor, poll_interval_seconds=0.005
    )
    spec = make_spec()
    await scheduler.start()
    try:
        await scheduler.submit(spec)
        await asyncio.wait_for(started.wait(), timeout=1)
        assert await scheduler.cancel(
            tenant_id=spec.tenant_id, task_id=spec.task_id
        )
        record = await wait_for_status(
            store, spec.tenant_id, spec.task_id, TaskStatus.CANCELLED
        )
        assert record.finished_at is not None
        assert not await scheduler.cancel(
            tenant_id=spec.tenant_id, task_id=spec.task_id
        )
    finally:
        await scheduler.stop()


def test_workflow_validation_rejects_cycles_and_unknown_dependencies():
    engine = WorkflowEngine(InMemoryRuntimeStore(), scheduler=None)
    tenant_id = uuid.uuid4()
    agent_id = uuid.uuid4()

    cycle = WorkflowSpec(
        tenant_id=tenant_id,
        name="cycle",
        version="1",
        steps=(
            WorkflowStepSpec("a", "task.a", agent_id, depends_on=("b",)),
            WorkflowStepSpec("b", "task.b", agent_id, depends_on=("a",)),
        ),
    )
    with pytest.raises(WorkflowValidationError, match="workflow_cycle_detected"):
        engine.validate(cycle)

    unknown = WorkflowSpec(
        tenant_id=tenant_id,
        name="unknown",
        version="1",
        steps=(
            WorkflowStepSpec("a", "task.a", agent_id, depends_on=("missing",)),
        ),
    )
    with pytest.raises(WorkflowValidationError, match="unknown_workflow_dependency"):
        engine.validate(unknown)


def test_workflow_validation_returns_deterministic_topological_plan():
    engine = WorkflowEngine(InMemoryRuntimeStore(), scheduler=None)
    tenant_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    spec = WorkflowSpec(
        tenant_id=tenant_id,
        name="linear",
        version="1",
        steps=(
            WorkflowStepSpec("child", "task.child", agent_id, depends_on=("parent",)),
            WorkflowStepSpec("parent", "task.parent", agent_id),
        ),
    )

    plan = engine.validate(spec)
    assert plan.ordered_steps.index("parent") < plan.ordered_steps.index("child")
    assert plan.workflow_id == engine.validate(spec).workflow_id


@pytest.mark.asyncio
async def test_store_rejects_direct_dependency_cycle():
    store = InMemoryRuntimeStore()
    tenant_id = uuid.uuid4()
    first = make_spec(tenant_id=tenant_id, kind="first")
    second = make_spec(tenant_id=tenant_id, kind="second")
    await store.create_task(first)
    await store.create_task(second)

    await store.add_dependency(tenant_id, first.task_id, second.task_id)
    with pytest.raises(ValueError, match="task_dependency_cycle"):
        await store.add_dependency(tenant_id, second.task_id, first.task_id)

    assert await store.list_task_dependencies(tenant_id, first.task_id) == {
        second.task_id
    }
    assert await store.list_task_dependencies(tenant_id, second.task_id) == set()


@pytest.mark.asyncio
async def test_store_rejects_indirect_dependency_cycle():
    store = InMemoryRuntimeStore()
    tenant_id = uuid.uuid4()
    first = make_spec(tenant_id=tenant_id, kind="first")
    second = make_spec(tenant_id=tenant_id, kind="second")
    third = make_spec(tenant_id=tenant_id, kind="third")
    for spec in (first, second, third):
        await store.create_task(spec)

    # first depends on second; second depends on third.
    await store.add_dependency(tenant_id, first.task_id, second.task_id)
    await store.add_dependency(tenant_id, second.task_id, third.task_id)

    # third -> first would close the transitive cycle.
    with pytest.raises(ValueError, match="task_dependency_cycle"):
        await store.add_dependency(tenant_id, third.task_id, first.task_id)

    assert await store.list_task_dependencies(tenant_id, third.task_id) == set()


@pytest.mark.asyncio
async def test_store_allows_acyclic_dependency_graph_and_duplicate_edge():
    store = InMemoryRuntimeStore()
    tenant_id = uuid.uuid4()
    root = make_spec(tenant_id=tenant_id, kind="root")
    middle = make_spec(tenant_id=tenant_id, kind="middle")
    leaf = make_spec(tenant_id=tenant_id, kind="leaf")
    for spec in (root, middle, leaf):
        await store.create_task(spec)

    await store.add_dependency(tenant_id, middle.task_id, root.task_id)
    await store.add_dependency(tenant_id, leaf.task_id, middle.task_id)
    # Re-registering an existing edge is idempotent.
    await store.add_dependency(tenant_id, leaf.task_id, middle.task_id)

    assert await store.list_task_dependencies(tenant_id, middle.task_id) == {
        root.task_id
    }
    assert await store.list_task_dependencies(tenant_id, leaf.task_id) == {
        middle.task_id
    }
