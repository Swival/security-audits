# State-changing ERL APIs falsely report success

## Classification
- Type: logic error
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/wiggle_abi/erl_impl.rs:24`
- `lib/src/erl.rs:14`
- `src/component/erl.rs:32`
- `src/component/erl.rs:41`
- `src/component/erl.rs:58`
- `test-fixtures/src/bin/edge-rate-limiting.rs:26`
- `test-fixtures/src/bin/edge-rate-limiting.rs:32`
- `cli/tests/integration/edge_rate_limiting.rs:11`

## Summary
`Session`'s `FastlyErl` implementation accepts state-changing ERL hostcalls but does not mutate any rate-counter or penalty-box state. Specifically, `ratecounter_increment` and `penaltybox_add` ignore all arguments and return `Ok(())`, causing callers to observe success while no counter increment or penalty entry is persisted.

## Provenance
- Verified from repository source and reproduced against the included ERL fixture and integration coverage.
- Scanner origin: https://swival.dev

## Preconditions
- Code path uses ERL `increment` or `penaltybox_add` APIs.

## Proof
In `src/wiggle_abi/erl_impl.rs:24`, guest ERL calls are routed into `Session`'s `FastlyErl` host implementation.
- `ratecounter_increment` accepts `_rc`, `_entry`, and `_delta` and immediately returns `Ok(())`.
- `penaltybox_add` accepts `_pb`, `_entry`, and `_ttl` and immediately returns `Ok(())`.
- Neither function reads nor writes `Session` state or any external store.

This behavior is reachable through the exported ERL surface referenced by `lib/src/erl.rs:14` and `src/component/erl.rs:32`, `src/component/erl.rs:41`, `src/component/erl.rs:58`.

The shipped fixture in `test-fixtures/src/bin/edge-rate-limiting.rs:26` and `test-fixtures/src/bin/edge-rate-limiting.rs:32` codifies the defect by asserting the mutating calls succeed while expecting follow-up lookup/has checks to remain zero/false. `cli/tests/integration/edge_rate_limiting.rs:11` only asserts a `200 OK` exit path, so the false-success behavior is not caught by integration coverage.

## Why This Is A Real Bug
The runtime advertises ERL hostcalls as available and returns success for mutating operations, creating a false contract: callers are told rate-limit accounting and penalty-box enforcement succeeded when no state change occurred. This can silently invalidate local testing and compatibility expectations by masking logic that would enforce limits in production. Returning success for a no-op state mutation is materially different from explicitly reporting the feature as unsupported.

## Fix Requirement
Implement persistence for ERL counter and penalty-box mutations, or return an explicit unsupported/unimplemented error instead of `Ok(())` for state-changing APIs.

## Patch Rationale
The patch in `042-state-changing-erl-apis-are-no-ops.patch` changes the mutating ERL hostcalls to stop falsely reporting success. This aligns observable behavior with actual capability and prevents callers from relying on nonexistent local state transitions.

## Residual Risk
None

## Patch
- `042-state-changing-erl-apis-are-no-ops.patch` updates `src/wiggle_abi/erl_impl.rs` so state-changing ERL APIs no longer behave as silent no-ops reporting success.