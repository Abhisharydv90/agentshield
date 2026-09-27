"""
Recomputes hash chains for all tenants.

Needed once, after the multi-tenancy migration: historical events were
written before `tenant_id` was part of the hash payload. This script walks
every tenant's chain oldest-to-newest, recomputes record_hash with the new
formula, and updates rows in place.

Run once:
    python scripts/rechain_audit.py

Idempotent: if a chain is already valid, it reports "already valid" and skips.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select
from app.db.session import async_session
from app.db.models import Tenant, SecurityEvent
from app.telemetry.audit import compute_hash, verify_chain


async def rechain_tenant(session, tenant: Tenant) -> dict:
    # Check current state
    before = await verify_chain(session, tenant.tenant_id)
    if before["valid"]:
        print(f"  [{tenant.slug}] chain already valid ({before['length']} events) — skipping")
        return {"tenant": tenant.slug, "before": before, "after": before, "updated": 0}

    # Walk oldest -> newest, rewrite hashes
    stmt = (
        select(SecurityEvent)
        .where(SecurityEvent.tenant_id == tenant.tenant_id)
        .order_by(SecurityEvent.timestamp.asc())
    )
    events = (await session.execute(stmt)).scalars().all()

    previous_hash: str | None = None
    updated = 0
    for e in events:
        payload = {
            "tenant_id": str(e.tenant_id),
            "request_id": e.request_id,
            "timestamp": e.timestamp.isoformat(),
            "threat_category": e.threat_category,
            "action_taken": e.action_taken,
            "evaluator_reasoning": e.evaluator_reasoning or "",
        }
        new_hash = compute_hash(previous_hash, payload)
        if e.prev_hash != previous_hash or e.record_hash != new_hash:
            e.prev_hash = previous_hash
            e.record_hash = new_hash
            updated += 1
        previous_hash = new_hash

    await session.commit()

    after = await verify_chain(session, tenant.tenant_id)
    print(f"  [{tenant.slug}] before: valid={before['valid']} · after: valid={after['valid']} · updated={updated}")
    return {"tenant": tenant.slug, "before": before, "after": after, "updated": updated}


async def main():
    async with async_session() as session:
        tenants = (await session.execute(select(Tenant))).scalars().all()
        print(f"Found {len(tenants)} tenant(s)")
        results = []
        for t in tenants:
            results.append(await rechain_tenant(session, t))

        print()
        print("=" * 64)
        for r in results:
            status = "✓" if r["after"]["valid"] else "✗"
            print(f"  {status} {r['tenant']}: {r['after']['length']} events, {r['updated']} rewritten")
        print("=" * 64)


asyncio.run(main())