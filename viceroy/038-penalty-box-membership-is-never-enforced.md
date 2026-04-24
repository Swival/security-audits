# Penalty box membership is never enforced

## Classification
- Type: authorization flaw
- Severity: high
- Confidence: certain

## Affected Locations
- `src/wiggle_abi/erl_impl.rs:57`
- `src/wiggle_abi/erl_impl.rs:46`

## Summary
`penaltybox_add` and `penaltybox_has` violate the ABI contract for ERL penalty boxes. The add path accepts guest-controlled box and entry inputs but stores nothing, while the has path always returns `0`. Any entry that is "added" is therefore immediately reported absent, so penalty-box-backed blocking or rate-limit behavior is never modeled.

## Provenance
- Reproduced from the verified finding and confirmed against repository sources
- ABI contract reference: `wasm_abi/wit/deps/fastly/compute.wit:1390`
- ABI contract reference: `wasm_abi/wit/deps/fastly/compute.wit:1398`
- Scanner reference: https://swival.dev

## Preconditions
- A caller relies on penalty box state for access-control, blocking, or rate-limit decisions during execution in Viceroy

## Proof
- In `src/wiggle_abi/erl_impl.rs:46`, `penaltybox_add` accepts `_pb` and `_entry` and returns `Ok(())` without persisting membership.
- In `src/wiggle_abi/erl_impl.rs:57`, `penaltybox_has` accepts `_pb` and `_entry` and unconditionally returns `Ok(0)`.
- The WIT contract states that add places an entry into the penalty box for a TTL and has checks whether the entry is present, but the implementation ignores both operations.
- Practical trigger: open a penalty box, call `add(entry, ttl)`, then call `has(entry)`; the second call always reports false.
- Reachability is direct through the exported ABI methods and already exercised by ERL fixture coverage such as `test-fixtures/src/bin/edge-rate-limiting.rs:28`.

## Why This Is A Real Bug
This is a concrete state-handling defect, not a theoretical mismatch. The implementation acknowledges penalty-box operations as successful while discarding the only state they are supposed to establish. That causes deterministic false negatives for any test or workflow expecting penalty-box membership to persist across calls. In this repository's context, Viceroy is a local runtime, so the practical impact is broken enforcement modeling and invalid test outcomes rather than production edge authorization bypass.

## Fix Requirement
Persist penalty-box entries in session state when `penaltybox_add` succeeds, keyed by penalty box and entry, and have `penaltybox_has` consult that stored state instead of returning a constant result.

## Patch Rationale
The patch in `038-penalty-box-membership-is-never-enforced.patch` implements the missing state flow: added entries are recorded in session state and membership checks read that state back. This aligns behavior with the WIT contract and restores expected ERL penalty-box semantics for fixtures and tests that depend on them.

## Residual Risk
None

## Patch
- Patch file: `038-penalty-box-membership-is-never-enforced.patch`
- Effect: records penalty-box membership on add and returns actual membership status on has
- Outcome: ERL penalty-box behavior is modeled consistently with the declared ABI contract