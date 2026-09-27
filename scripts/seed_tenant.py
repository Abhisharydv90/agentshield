"""
Create the initial "default" tenant + a dev API key.

Usage:
    python scripts/seed_tenant.py

Idempotent — safe to re-run. Prints the API key on first creation.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select
from app.db.session import async_session
from app.db.models import Tenant, APIKey
from app.security.api_keys import generate_key, hash_key, key_prefix


async def main() -> None:
    async with async_session() as session:
        # Create or fetch default tenant
        stmt = select(Tenant).where(Tenant.slug == "default")
        tenant = (await session.execute(stmt)).scalar_one_or_none()

        if tenant is None:
            tenant = Tenant(slug="default", name="Default Tenant")
            session.add(tenant)
            await session.flush()
            print(f"✓ Created tenant: {tenant.slug} ({tenant.tenant_id})")
        else:
            print(f"✓ Tenant already exists: {tenant.slug} ({tenant.tenant_id})")

        # Create a dev API key if none exist
        stmt = select(APIKey).where(APIKey.tenant_id == tenant.tenant_id)
        existing = (await session.execute(stmt)).scalars().all()

        if not existing:
            raw_key = generate_key(live=False)
            api_key = APIKey(
                tenant_id=tenant.tenant_id,
                name="default-dev-key",
                key_prefix=key_prefix(raw_key),
                key_hash=hash_key(raw_key),
            )
            session.add(api_key)
            await session.commit()
            print()
            print("=" * 60)
            print("  NEW API KEY (save this — it will not be shown again)")
            print("=" * 60)
            print(f"  {raw_key}")
            print("=" * 60)
            print()
        else:
            await session.commit()
            print(f"✓ {len(existing)} API key(s) already exist for this tenant")

asyncio.run(main())