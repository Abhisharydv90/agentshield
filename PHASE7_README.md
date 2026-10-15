# AURAGENT Phase 7 — Isolation Fabric

Phase 7 implements the AURAGENT Execution & Isolation Layer described by the
master architecture:

- Container sandboxing
- Process-isolation contract with fail-closed unsupported host backend
- Filesystem boundaries
- Network control
- CPU / memory / PID / time / output quotas
- Device boundaries
- Environment templates
- Non-root execution
- Read-only root filesystem
- no-new-privileges
- Drop-all-capabilities baseline

## Enforcement model

The Phase 4 SecurityContext remains the authority boundary. Phase 7 does not
grant capabilities. It only consumes existing authority and rejects missing
capabilities.

The default container network is `none`.

Domain-level external egress is intentionally rejected unless a managed egress
proxy/firewall is configured and an enforcement backend is wired. The code does
not treat a Docker bridge network as a domain allowlist.

Docker images are never auto-pulled. The backend requires the image to already
exist locally, which prevents an isolation request from silently creating an
unreviewed network dependency.

Filesystem host binds require explicit allowed host roots. Mounts are
read-only by default, and read-write mounts require `filesystem:write`.

Raw secret material is not accepted through Phase 7 environment variables.
Secret access remains behind the Phase 5 secret boundary.

## Current operational requirement

Strong container execution requires a working Docker Engine and a locally
available image such as `python:3.12-slim`. This implementation does not claim
that a plain host subprocess is equivalent to a security container.
