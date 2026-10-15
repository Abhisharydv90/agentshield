# AURAGENT Phase 9 — Security Lab

Phase 9 is the **Security Lab** layer of AURAGENT. It is designed to test the
security boundaries created in Phases 4–8 rather than replace them.

## Included

- **AttackForge:** stable built-in red-team scenario catalog.
- **SecurityBench:** deterministic regression/benchmark runs.
- **Fuzzing:** bounded, seeded, in-memory mutators.
- **Regression corpus:** append-only content-addressed test cases.
- **Reports:** versioned, hash-committed run reports.
- **Tenant isolation:** lab state is partitioned by tenant.
- **Admin API:** scenario discovery, runs, benchmark, corpus and run history.
- **Future-phase contract:** Phase 10 investigation can consume `run_id`,
  `scenario_id`, `case_id`, `finding`, `evidence_root`, and `report_hash`
  without requiring Phase 9 source changes.

## Security model

The lab never treats attacker payloads as executable instructions. It does not
perform network attacks, start shell commands, retrieve secrets, or deploy
exploits. Default execution uses the local reference simulation. Production
integration tests can provide a LabTarget that invokes AURAGENT's existing
Phase 4 security kernel, Phase 5 tool dispatcher, Phase 6 memory controls, and
Phase 7 isolation boundary.

The scenario taxonomy follows five execution layers useful for agent security:
input, external data, tool/protocol, memory, and multi-agent authority flow.
The central regression property is that untrusted content cannot acquire
authority merely by appearing in a prompt, document, tool response, memory
record, or delegated message.

## Persistence and scaling note

The Phase 9 corpus and run history are intentionally process-local. Persistence
is deferred to later AURAGENT data/control/scale phases so the Phase 9 contracts
remain stable while storage can move to PostgreSQL/object storage/event streams.

## Files

See `PHASE9_MANIFEST.json` for the authoritative Phase 9-owned file set.
