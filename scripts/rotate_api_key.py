"""
Regenerates the default-tenant API key.

Usage:
    python scripts/rotate_api_key.py

Revokes all existing keys for the default tenant and issues a fresh one.
Prints the new key. Save it immediately.
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
        tenant = (
            await session.execute(select(Tenant).where(Tenant.slug == "default"))
        ).scalar_one_or_none()

        if tenant is None:
            print("✗ No default tenant. Run scripts/seed_tenant.py first.")
            return

        # Revoke all existing keys for this tenant
        existing = (
            await session.execute(
                select(APIKey).where(APIKey.tenant_id == tenant.tenant_id)
            )
        ).scalars().all()

        for k in existing:
            k.revoked = True
        await session.flush()
        print(f"✓ Revoked {len(existing)} existing key(s)")

        # Generate a fresh key
        raw_key = generate_key(live=False)
        new_key = APIKey(
            tenant_id=tenant.tenant_id,
            name="default-dev-key",
            key_prefix=key_prefix(raw_key),
            key_hash=hash_key(raw_key),
        )
        session.add(new_key)
        await session.commit()

        print()
        print("=" * 64)
        print("  NEW API KEY")
        print("=" * 64)
        print(f"  {raw_key}")
        print("=" * 64)
        print("  Copy the key EXACTLY. No ambiguous characters used.")
        print("=" * 64)
        print()


asyncio.run(main())