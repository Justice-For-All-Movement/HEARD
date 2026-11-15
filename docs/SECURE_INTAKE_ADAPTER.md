# Secure Intake & Case Workflow Engine adapter (HEARD-05)

HEARD reaches case workflow only through `packages/secure-intake` (contract version `1.0.0`). The machine-readable compatibility manifest is [`contracts/secure-intake-boundary.v1.json`](../contracts/secure-intake-boundary.v1.json); a test keeps it identical to the implementation.

## Implementations

| Mode | Status | Behaviour |
|---|---|---|
| `local` (default) | Implemented and tested on native PostgreSQL 17 | HEARD-owned workflow on `heard_cases` and append-only `heard_case_events`, executed inside the caller's RLS-scoped transaction. Capabilities: create draft, submit, withdraw, read status, record event, start review. |
| `remote` | **Blocked** | The upstream engine's API, version, token audience and event-signing contract have not been verified against a real deployment. `VERIFIED_UPSTREAM_VERSIONS` is empty, so the remote adapter makes no network call, every operation fails with `UPSTREAM_CONTRACT_UNVERIFIED`, and `/api/ready` is not ready when intake is enabled in remote mode. |

There is **no implicit fallback**: selecting `remote` never silently uses the local adapter, and unknown modes fail at startup.

## Contract invariants (tested)

- Case states: `draft → submitted → review → closed`, any non-terminal state → `withdrawn`; `closed` and `withdrawn` are terminal. Transitions are compare-and-set, so replays and concurrent submissions fail with `ADAPTER_STATE_CONFLICT` (exactly one of three concurrent submits wins).
- Case events accept only allowlisted short scalar metadata (`schemaVersion`, `policyVersion`, `reason`, `channel`); narrative text, contact data and unknown keys are rejected (`ADAPTER_UNSAFE_METADATA`) and roll back the surrounding transaction.
- Missing and unauthorized cases are indistinguishable (`ADAPTER_NOT_FOUND`); malformed IDs fail before any query.
- Features must call `requireCapability`; unsupported capabilities (`case.assign_reviewer`, `case.helper_grant`) fail with `ADAPTER_CAPABILITY_UNSUPPORTED` rather than degrading.

## To verify the remote engine (blocker)

1. Obtain the engine's published OpenAPI/event specification and a deployed, isolated test instance.
2. Implement the HTTP calls in `createRemoteAdapter` against that exact version, including token audience/expiry, signed webhook verification with replay windows and idempotency keys.
3. Run the same contract cases as `tests/server/secure-intake.test.mjs` against the test instance, then add the version to `VERIFIED_UPSTREAM_VERSIONS` and the manifest with links to the evidence.

Until then HEARD uses the local adapter. This document makes no claim of upstream compatibility.
