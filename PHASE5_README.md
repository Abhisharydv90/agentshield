# AURAGENT Phase 5 — Tool Fabric

Implementation target from the AURAGENT 0-15 roadmap:

- Tool registry
- Tool manifests/contracts
- Resource authorization
- MCP client/session boundary
- Browser/computer-use policy boundary
- Secret boundary
- Custom tool loader
- Security-aware tool dispatcher

## Apply

From `D:\dev\agentshield` in PowerShell:

```powershell
.\APPLY_PHASE5.ps1
```

The script overwrites only the Phase 5 target files listed in the manifest and the Phase 5 integration roots (`app/main.py`, `app/proxy/router.py`). It does not run Git commands.

## Security boundary

`ToolDispatcher` requires a Phase 4 `SecurityContext`. It validates the tool manifest, required capabilities, operation authority, resource scope, network scope and deterministic risk before invoking the handler.

MCP, browser, secrets and custom modules are boundaries behind the dispatcher; none of them grants authority by itself.

## Verification policy

Per the project build-first workflow, Phase 5 code is prepared for comprehensive testing later. Do not treat the phase as finally verified until the whole AURAGENT platform is assembled and the final integration suite passes.
