# AURAGENT — Phase 11 Control Plane

Phase 11 is the administrative, organizational, and accounting layer for
AURAGENT.

## Implemented

- organization administration over existing `Tenant`
- persistent logical projects stored under a reserved key in existing
  `TenantSettings` JSON configuration
- owner/admin/member RBAC
- explicit deny-by-default ABAC
- configuration versioning with immutable security keys
- API-key inventory that never exposes secret material
- bounded request-usage aggregation over existing `RequestLog`
- dashboard TypeScript client

## No new database migration

The AURAGENT foundation already persists `Tenant`, `TenantSettings`, `User`,
`APIKey`, and `RequestLog`. Phase 11 composes those existing stores rather
than adding another persistence layer. Project records are stored in the
existing tenant settings JSON object under `_auragent_projects`.

The service fails closed if the current `TenantSettings` model has no supported
JSON-like configuration column.

## Projects

Project IDs are deterministic and tenant-bound:

`sha256(tenant_id + normalized_project_name)`

Project create/list/delete APIs operate only inside the server-resolved tenant
scope.

## Configuration

Direct configuration PATCH rejects reserved keys and immutable security
authority keys. Project records are managed only by project APIs.

## API keys

Phase 11 provides safe inventory/metadata. Secret values, hashes, and complete
credentials are never returned. Credential creation/rotation/revocation
continue to live in the authentication boundary rather than creating a second
secret authority.

## Usage

Usage is explicitly provider-neutral. `estimated_usage_units` is a bounded
request-unit accounting measure and is not presented as an authoritative
cloud/provider bill.

## Security model

Every mutation requires:

1. authenticated user
2. server-resolved tenant
3. RBAC permission
4. ABAC resource/action check
5. tenant-scoped persistence

The Control Plane does not grant, delegate, or increase agent authority.

## Router

No rewrite of the AURAGENT composition root is required. The existing dynamic
router registration is expected to discover:

`app.api.control_plane`

## Verification

The installer performs no repository tests, Alembic operations, frontend
build, or final E2E verification. Those remain part of the AURAGENT 0–15 final
verification pass.
