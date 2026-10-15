"""Durable, tenant-safe Memory Fabric store."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Mapping

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.memory_models import MemoryLineage, MemoryRecord, MemorySource, MemoryVersion
from app.memory.models import (
    InfluenceClass,
    MemoryCreate,
    MemoryKind,
    MemoryRecordView,
    MemorySearchQuery,
    MemorySearchResult,
    MemoryStatus,
    MemoryUpdate,
)
from app.memory.provenance.lineage import lineage_fingerprint
from app.memory.provenance.source import SourceDescriptor, SourceVerifier
from app.memory.retention import DEFAULT_RETENTION_POLICY, RetentionPolicy
from app.memory.security.poisoning import MemoryPoisoningVerdict, scan_memory
from app.memory.security.validation import (
    MemoryValidationError,
    content_hash,
    validate_content,
    validate_key,
    validate_namespace,
    verify_content_hash,
)
from app.memory.semantic.index import DeterministicEmbeddingProvider
from app.memory.semantic.retrieval import MemoryRetriever
from app.security.context import SecurityContext


class MemorySecurityError(ValueError):
    """Raised when a memory operation violates a security invariant."""


class VersionConflictError(MemorySecurityError):
    """Raised when optimistic version control detects a stale writer."""


class MemoryNotFoundError(MemorySecurityError):
    """Raised when a memory is absent or tenant scoped away."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if value else None


class MemoryStore:
    """All memory access is mediated by authenticated SecurityContext."""

    def __init__(
        self,
        session: AsyncSession,
        *,
        retention: RetentionPolicy | None = None,
    ) -> None:
        self.session = session
        self.retention = retention or DEFAULT_RETENTION_POLICY
        self.embedder = DeterministicEmbeddingProvider()
        self.retriever = MemoryRetriever(self.embedder)
        self.source_verifier = SourceVerifier()

    @staticmethod
    def _require_capability(context: SecurityContext, capability: str, operation: str) -> None:
        if capability not in context.capabilities:
            raise MemorySecurityError(f"missing_memory_capability:{capability}")
        if operation not in context.authority.operations:
            raise MemorySecurityError(f"memory_operation_outside_authority:{operation}")

    @staticmethod
    def _namespace_allowed(context: SecurityContext, namespace: str) -> bool:
        scopes = context.authority.data_scopes.values
        if not scopes:
            return True
        candidates = {
            f"memory:{namespace}",
            namespace,
        }
        return any(
            candidate in scopes
            or any(grant.endswith("/") and candidate.startswith(grant) for grant in scopes)
            for candidate in candidates
        )

    def _assert_scope(self, context: SecurityContext, namespace: str) -> None:
        if not self._namespace_allowed(context, namespace):
            raise MemorySecurityError("memory_namespace_outside_authority")

    def _parse_source(self, source: Mapping[str, Any] | None) -> SourceDescriptor | None:
        if source is None:
            return None
        return SourceDescriptor(
            source_type=str(source.get("source_type", "unknown")).strip() or "unknown",
            uri=str(source["uri"]).strip() if source.get("uri") else None,
            title=str(source["title"]).strip() if source.get("title") else None,
            expected_content_hash=(
                str(source["expected_content_hash"]).strip()
                if source.get("expected_content_hash")
                else None
            ),
            metadata=dict(source.get("metadata") or {}),
        )

    async def _create_source(
        self,
        *,
        context: SecurityContext,
        content: str,
        source: SourceDescriptor | None,
    ) -> tuple[MemorySource | None, str, str]:
        verification = self.source_verifier.verify(
            content=content,
            source=source,
        )
        row = None

        if source is not None:
            now = _utc_now()
            row = MemorySource(
                tenant_id=context.tenant_id,
                source_type=source.source_type,
                uri=source.uri,
                title=source.title,
                expected_content_hash=source.expected_content_hash,
                content_hash=verification.content_hash,
                verified=verification.verified,
                trust_class=verification.trust_class,
                verification_method=verification.method,
                reason=verification.reason,
                metadata_json=dict(source.metadata or {}),
                created_at=now,
                verified_at=now if verification.verified else None,
            )
            self.session.add(row)
            await self.session.flush()

        return row, verification.content_hash, verification.trust_class

    def _poisoning_failure(
        self,
        verdict: MemoryPoisoningVerdict,
        on_poisoning: str,
    ) -> tuple[bool, str]:
        if not verdict.suspicious:
            return False, "clean"
        if on_poisoning == "quarantine":
            return True, "quarantined"
        raise MemorySecurityError(
            "memory_poisoning_rejected:"
            + ",".join(verdict.reasons[:5])
        )

    def _view(self, row: MemoryRecord) -> MemoryRecordView:
        return MemoryRecordView(
            memory_id=str(row.memory_id),
            tenant_id=str(row.tenant_id),
            agent_id=str(row.agent_id),
            namespace=row.namespace,
            key=row.memory_key,
            kind=row.kind,
            content=row.content,
            content_hash=row.content_hash,
            version=row.current_version,
            status=row.status,
            trust_class=row.trust_class,
            influence_class=row.influence_class,
            source_id=str(row.source_id) if row.source_id else None,
            retention_until=_iso(row.retention_until),
            metadata=dict(row.metadata_json or {}),
        )

    async def _load(self, context: SecurityContext, memory_id: uuid.UUID) -> MemoryRecord:
        self._require_capability(context, "memory:read", "read")
        row = (
            await self.session.execute(
                select(MemoryRecord)
                .where(MemoryRecord.memory_id == memory_id)
                .where(MemoryRecord.tenant_id == context.tenant_id)
            )
        ).scalar_one_or_none()

        if row is None or row.status == MemoryStatus.DELETED.value:
            raise MemoryNotFoundError("memory_not_found")

        self._assert_scope(context, row.namespace)

        if not verify_content_hash(row.content, row.content_hash):
            raise MemorySecurityError("memory_integrity_check_failed")

        verdict = scan_memory(row.content)
        if verdict.suspicious or row.status == MemoryStatus.QUARANTINED.value:
            raise MemorySecurityError("memory_quarantined_or_poisoned")

        return row

    async def create(
        self,
        context: SecurityContext,
        request: MemoryCreate,
    ) -> MemoryRecordView:
        self._require_capability(context, "memory:write", "write")

        try:
            namespace = validate_namespace(request.namespace)
            key = validate_key(request.key)
            content = validate_content(request.content)
        except MemoryValidationError as exc:
            raise MemorySecurityError(str(exc)) from exc

        self._assert_scope(context, namespace)

        existing = (
            await self.session.execute(
                select(MemoryRecord)
                .where(MemoryRecord.tenant_id == context.tenant_id)
                .where(MemoryRecord.namespace == namespace)
                .where(MemoryRecord.memory_key == key)
                .where(MemoryRecord.status != MemoryStatus.DELETED.value)
            )
        ).scalar_one_or_none()

        if existing is not None:
            raise MemorySecurityError("memory_key_already_exists")

        verdict = scan_memory(content)
        should_quarantine, _ = self._poisoning_failure(verdict, request.on_poisoning)

        source = self._parse_source(request.source)
        source_row, digest, trust_class = await self._create_source(
            context=context,
            content=content,
            source=source,
        )

        now = _utc_now()
        memory_id = uuid.uuid4()
        retention_until = self.retention.expires_at(
            kind=request.kind,
            created_at=now,
            override_days=request.retention_days,
        )

        status = (
            MemoryStatus.QUARANTINED.value
            if should_quarantine
            else MemoryStatus.ACTIVE.value
        )

        # Influence is metadata only.  It is never authority.
        influence_class = (
            InfluenceClass.UNTRUSTED.value
            if request.kind == MemoryKind.EXTERNAL
            else request.kind.value
        )

        row = MemoryRecord(
            memory_id=memory_id,
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            namespace=namespace,
            memory_key=key,
            kind=request.kind.value,
            content=content,
            content_hash=digest,
            current_version=1,
            status=status,
            trust_class=trust_class,
            influence_class=influence_class,
            source_id=source_row.source_id if source_row else None,
            retention_until=retention_until,
            metadata_json=dict(request.metadata),
            created_at=now,
            updated_at=now,
        )
        self.session.add(row)
        await self.session.flush()

        embedding = self.embedder.embed(content)
        version_hash = content_hash({
            "schema": "auragent.memory-version.v1",
            "memory_id": str(memory_id),
            "version_number": 1,
            "content_hash": digest,
            "previous_version_hash": None,
            "embedding": embedding,
            "writer_agent_id": str(context.agent_id),
            "source_id": str(source_row.source_id) if source_row else None,
            "metadata": dict(request.metadata),
        })
        version = MemoryVersion(
            tenant_id=context.tenant_id,
            memory_id=memory_id,
            version_number=1,
            content=content,
            content_hash=digest,
            version_hash=version_hash,
            previous_version_hash=None,
            embedding=embedding,
            writer_agent_id=context.agent_id,
            source_id=source_row.source_id if source_row else None,
            metadata_json=dict(request.metadata),
            created_at=now,
        )
        self.session.add(version)
        await self.session.flush()

        record_hash = await self._append_lineage(
            context=context,
            memory=row,
            version=version,
            operation="created",
            metadata={
                "poisoning_score": verdict.score,
                "quarantined": should_quarantine,
            },
        )
        await self.session.flush()

        # Never encode authority into memory metadata.
        row.metadata_json = {
            **dict(request.metadata),
            "memory_security": {
                "content_hash": digest,
                "poisoning_score": verdict.score,
                "lineage_hash": record_hash,
                "authority_influence_separation": True,
            },
        }

        return self._view(row)

    async def get(
        self,
        context: SecurityContext,
        memory_id: uuid.UUID,
    ) -> MemoryRecordView:
        row = await self._load(context, memory_id)
        return self._view(row)

    async def update(
        self,
        context: SecurityContext,
        memory_id: uuid.UUID,
        request: MemoryUpdate,
    ) -> MemoryRecordView:
        self._require_capability(context, "memory:write", "write")

        row = (
            await self.session.execute(
                select(MemoryRecord)
                .where(MemoryRecord.memory_id == memory_id)
                .where(MemoryRecord.tenant_id == context.tenant_id)
                .with_for_update()
            )
        ).scalar_one_or_none()

        if row is None or row.status == MemoryStatus.DELETED.value:
            raise MemoryNotFoundError("memory_not_found")

        self._assert_scope(context, row.namespace)

        if row.current_version != request.expected_version:
            raise VersionConflictError(
                f"memory_version_conflict:expected={request.expected_version}:actual={row.current_version}"
            )

        content = validate_content(request.content)
        verdict = scan_memory(content)
        should_quarantine, _ = self._poisoning_failure(verdict, request.on_poisoning)

        source = self._parse_source(request.source)
        source_row, digest, trust_class = await self._create_source(
            context=context,
            content=content,
            source=source,
        )

        previous_version = (
            await self.session.execute(
                select(MemoryVersion)
                .where(MemoryVersion.memory_id == memory_id)
                .where(MemoryVersion.tenant_id == context.tenant_id)
                .where(MemoryVersion.version_number == row.current_version)
            )
        ).scalar_one()

        new_version_number = row.current_version + 1
        embedding = self.embedder.embed(content)
        version_hash = content_hash({
            "schema": "auragent.memory-version.v1",
            "memory_id": str(memory_id),
            "version_number": new_version_number,
            "content_hash": digest,
            "previous_version_hash": previous_version.version_hash,
            "embedding": embedding,
            "writer_agent_id": str(context.agent_id),
            "source_id": str(source_row.source_id) if source_row else None,
            "metadata": dict(request.metadata or row.metadata_json or {}),
        })
        version = MemoryVersion(
            tenant_id=context.tenant_id,
            memory_id=memory_id,
            version_number=new_version_number,
            content=content,
            content_hash=digest,
            version_hash=version_hash,
            previous_version_hash=previous_version.version_hash,
            embedding=embedding,
            writer_agent_id=context.agent_id,
            source_id=source_row.source_id if source_row else None,
            metadata_json=dict(request.metadata or row.metadata_json or {}),
            created_at=_utc_now(),
        )
        self.session.add(version)
        await self.session.flush()

        row.content = content
        row.content_hash = digest
        row.current_version = new_version_number
        row.status = (
            MemoryStatus.QUARANTINED.value if should_quarantine else MemoryStatus.ACTIVE.value
        )
        row.trust_class = trust_class
        row.influence_class = (
            InfluenceClass.UNTRUSTED.value
            if row.kind == MemoryKind.EXTERNAL.value
            else row.kind
        )
        row.source_id = source_row.source_id if source_row else None
        row.retention_until = self.retention.expires_at(
            kind=row.kind,
            created_at=row.created_at,
            override_days=request.retention_days,
        )
        row.metadata_json = {
            **dict(request.metadata or row.metadata_json or {}),
            "memory_security": {
                "content_hash": digest,
                "poisoning_score": verdict.score,
            },
        }
        row.updated_at = _utc_now()

        record_hash = await self._append_lineage(
            context=context,
            memory=row,
            version=version,
            operation="updated",
            metadata={
                "poisoning_score": verdict.score,
                "quarantined": should_quarantine,
                "previous_version_hash": previous_version.version_hash,
            },
        )
        row.metadata_json = {
            **dict(row.metadata_json or {}),
            "memory_security": {
                **dict((row.metadata_json or {}).get("memory_security", {})),
                "lineage_hash": record_hash,
            },
        }

        return self._view(row)

    async def delete(self, context: SecurityContext, memory_id: uuid.UUID) -> None:
        self._require_capability(context, "memory:write", "write")
        row = (
            await self.session.execute(
                select(MemoryRecord)
                .where(MemoryRecord.memory_id == memory_id)
                .where(MemoryRecord.tenant_id == context.tenant_id)
                .with_for_update()
            )
        ).scalar_one_or_none()

        if row is None:
            raise MemoryNotFoundError("memory_not_found")

        self._assert_scope(context, row.namespace)

        row.status = MemoryStatus.DELETED.value
        row.updated_at = _utc_now()

        await self._append_lineage(
            context=context,
            memory=row,
            version=None,
            operation="deleted",
            metadata={},
        )

    async def search(
        self,
        context: SecurityContext,
        request: MemorySearchQuery,
    ) -> list[MemorySearchResult]:
        self._require_capability(context, "memory:read", "read")

        stmt = (
            select(MemoryRecord)
            .where(MemoryRecord.tenant_id == context.tenant_id)
            .where(MemoryRecord.status == MemoryStatus.ACTIVE.value)
        )

        if request.namespace:
            namespace = validate_namespace(request.namespace)
            self._assert_scope(context, namespace)
            stmt = stmt.where(MemoryRecord.namespace == namespace)

        if request.kind:
            stmt = stmt.where(MemoryRecord.kind == request.kind.value)

        rows = (await self.session.execute(stmt.limit(500))).scalars().all()

        candidates = []
        candidate_rows = []
        for row in rows:
            if not self._namespace_allowed(context, row.namespace):
                continue
            if not verify_content_hash(row.content, row.content_hash):
                continue
            verdict = scan_memory(row.content)
            if verdict.suspicious:
                continue
            version = (
                await self.session.execute(
                    select(MemoryVersion)
                    .where(MemoryVersion.tenant_id == context.tenant_id)
                    .where(MemoryVersion.memory_id == row.memory_id)
                    .where(MemoryVersion.version_number == row.current_version)
                )
            ).scalar_one_or_none()
            if version is None:
                continue
            candidates.append(
                __import__("app.memory.semantic.retrieval", fromlist=["RetrievalCandidate"]).RetrievalCandidate(
                    memory_id=row.memory_id,
                    content=row.content,
                    content_hash=row.content_hash,
                    embedding=list(version.embedding or []),
                    metadata={"namespace": row.namespace, "key": row.memory_key},
                )
            )
            candidate_rows.append((row, verdict))

        scored = self.retriever.score(query=request.query, candidates=candidates)
        result_by_id = {str(candidate.memory_id): (candidate, score, poison) for candidate, score, poison in scored}

        output = []
        for row, _verdict in candidate_rows:
            item = result_by_id.get(str(row.memory_id))
            if item is None:
                continue
            _, score, poison_score = item
            if score < request.min_score:
                continue
            output.append(
                MemorySearchResult(
                    memory=self._view(row),
                    score=score,
                    integrity_verified=True,
                    poisoning_score=poison_score,
                    provenance={
                        "memory_id": str(row.memory_id),
                        "version": row.current_version,
                        "namespace": row.namespace,
                        "influence_class": row.influence_class,
                        "authority_grant": None,
                        "note": "retrieved memory may influence reasoning but does not confer authority",
                    },
                )
            )

        output.sort(key=lambda item: (-item.score, item.memory.memory_id))
        return output[:request.limit]

    async def _append_lineage(
        self,
        *,
        context: SecurityContext,
        memory: MemoryRecord,
        version: MemoryVersion | None,
        operation: str,
        metadata: Mapping[str, Any],
    ) -> str:
        previous = (
            await self.session.execute(
                select(MemoryLineage.record_hash)
                .where(MemoryLineage.tenant_id == context.tenant_id)
                .where(MemoryLineage.memory_id == memory.memory_id)
                .order_by(MemoryLineage.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

        digest = lineage_fingerprint(
            tenant_id=str(context.tenant_id),
            memory_id=str(memory.memory_id),
            version_id=str(version.version_id) if version else None,
            operation=operation,
            actor_agent_id=str(context.agent_id),
            content_hash=memory.content_hash,
            previous_lineage_hash=previous,
            metadata=metadata,
        )
        row = MemoryLineage(
            tenant_id=context.tenant_id,
            memory_id=memory.memory_id,
            version_id=version.version_id if version else None,
            actor_agent_id=context.agent_id,
            operation=operation,
            influence_class=memory.influence_class,
            content_hash=memory.content_hash,
            previous_lineage_hash=previous,
            record_hash=digest,
            metadata_json=dict(metadata),
            created_at=_utc_now(),
        )
        self.session.add(row)
        await self.session.flush()
        return digest

    async def purge_expired(self, *, tenant_id: uuid.UUID | None = None) -> int:
        now = _utc_now()
        stmt = (
            delete(MemoryRecord)
            .where(MemoryRecord.status != MemoryStatus.DELETED.value)
            .where(MemoryRecord.retention_until.is_not(None))
            .where(MemoryRecord.retention_until <= now)
        )
        if tenant_id is not None:
            stmt = stmt.where(MemoryRecord.tenant_id == tenant_id)
        result = await self.session.execute(stmt)
        return int(result.rowcount or 0)
