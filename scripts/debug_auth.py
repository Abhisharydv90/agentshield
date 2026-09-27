"""
One-off debug script. Prints the exact hash and does the exact query
that the middleware does. Tells us whether the problem is hashing or the query.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select
from app.db.session import async_session
from app.db.models import Tenant, APIKey
from app.security.api_keys import hash_key

KEY = "ask_test_hEPst0E32VusLGmITYIPQnyRKaGgHUjvJmuPwBRD"


async def main():
    computed = hash_key(KEY)
    print(f"\n[1] Key being tested: {KEY}")
    print(f"[1] Length: {len(KEY)}")
    print(f"[2] Computed hash: {computed}")

    async with async_session() as session:
        # All API keys
        all_keys = (await session.execute(select(APIKey))).scalars().all()
        print(f"\n[3] Total API keys in DB: {len(all_keys)}")
        for k in all_keys:
            print(f"    prefix={k.key_prefix!r}  hash={k.key_hash[:24]}...  revoked={k.revoked}")

        # Direct lookup
        stmt = select(APIKey).where(APIKey.key_hash == computed)
        found = (await session.execute(stmt)).scalar_one_or_none()
        print(f"\n[4] Lookup by hash alone: {'FOUND' if found else 'NOT FOUND'}")

        if found:
            print(f"    key_id={found.key_id}")
            print(f"    tenant_id={found.tenant_id}")
            print(f"    revoked={found.revoked!r} (type {type(found.revoked).__name__})")

            # Now the join
            t = (await session.execute(
                select(Tenant).where(Tenant.tenant_id == found.tenant_id)
            )).scalar_one_or_none()
            if t:
                print(f"    tenant.slug={t.slug!r}  tenant.status={t.status!r}")

        # Full joined query — same as middleware
        row = (await session.execute(
            select(APIKey, Tenant)
            .join(Tenant, Tenant.tenant_id == APIKey.tenant_id)
            .where(APIKey.key_hash == computed)
            .where(APIKey.revoked.is_(False))
            .where(Tenant.status == "active")
        )).first()
        print(f"\n[5] Full joined query: {'FOUND' if row else 'NOT FOUND'}")


asyncio.run(main())