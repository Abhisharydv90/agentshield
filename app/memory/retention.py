"""Retention policies for durable agent memory."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.memory.models import MemoryKind


@dataclass(frozen=True)
class RetentionPolicy:
    default_days: int = 90
    user_days: int = 365
    agent_days: int = 180
    tool_days: int = 30
    external_days: int = 30
    summary_days: int = 180
    system_days: int = 3650

    def days_for(self, kind: MemoryKind | str) -> int:
        value = MemoryKind(kind)
        return {
            MemoryKind.USER: self.user_days,
            MemoryKind.AGENT: self.agent_days,
            MemoryKind.TOOL: self.tool_days,
            MemoryKind.EXTERNAL: self.external_days,
            MemoryKind.SUMMARY: self.summary_days,
            MemoryKind.SYSTEM: self.system_days,
        }[value]

    def expires_at(
        self,
        *,
        kind: MemoryKind | str,
        created_at: datetime | None = None,
        override_days: int | None = None,
    ) -> datetime:
        created = created_at or datetime.now(timezone.utc)
        days = self.days_for(kind) if override_days is None else override_days
        if days <= 0:
            raise ValueError("retention days must be positive")
        return created + timedelta(days=days)

    @staticmethod
    def expired(expires_at: datetime | None, now: datetime | None = None) -> bool:
        if expires_at is None:
            return False
        current = now or datetime.now(timezone.utc)
        return expires_at <= current


DEFAULT_RETENTION_POLICY = RetentionPolicy()
