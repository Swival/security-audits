# Counter and penalty mutations are silently discarded

## Classification
- Type: data integrity bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/component/erl.rs:4`
- `src/component/erl.rs:15`
- `src/component/erl.rs:20`
- `src/component/erl.rs:36`
- `src/wiggle_abi/erl_impl.rs:8`
- `src/component.rs:114`
- `src/component.rs:115`
- `src/linking.rs:347`

## Summary
ERL mutation APIs report success while performing no state change. `check_rate`, `ratecounter_increment`, and `penaltybox_add` ignore their inputs and return success-only defaults, so callers observe empty counters and penalty boxes even after successful mutation calls.

## Provenance
- Verified from the supplied reproducer and source inspection
- Reproduced against the exposed component and legacy ABI surfaces
- Reference: https://swival.dev

## Preconditions
- A caller relies on ERL APIs to persist counters or penalty entries
- The caller uses either the component ERL bindings or the legacy `fastly_erl` ABI
- The caller treats successful return values as evidence that mutations were applied

## Proof
In `src/component/erl.rs:4`, `src/component/erl.rs:15`, and `src/component/erl.rs:36`, the ERL entrypoints accept session handles, keys, deltas, and TTLs but do not read or write any backing state. They return `Ok(false)`, `Ok(0)`, or `Ok(())` unconditionally. Because `src/component.rs:114` and `src/component.rs:115` expose these interfaces to guests, a guest can invoke the APIs successfully while all mutation data is dropped. The same behavior is mirrored on the legacy path through `src/linking.rs:347` and `src/wiggle_abi/erl_impl.rs:8`, where the ABI also returns success-only defaults. This reproduces the observed sequence: mutate, then check, and always receive a false negative without error.

## Why This Is A Real Bug
The behavior violates the contract implied by the API surface: mutation calls succeed, but no mutation occurs. This is not a harmless stub because unsupported APIs elsewhere return explicit `Error::Unsupported`, allowing callers to branch safely. Here, callers cannot distinguish “unsupported” from “empty state,” so rate limiting and penalty enforcement logic can be bypassed or disabled silently.

## Fix Requirement
Implement real backing-state reads and writes for ERL counters and penalty boxes, or return an explicit unsupported error on every unimplemented ERL mutation and lookup path instead of success defaults.

## Patch Rationale
The patch in `036-counter-and-penalty-mutations-are-silently-discarded.patch` replaces silent success defaults with explicit unsupported failures on the affected ERL paths. This preserves data integrity by preventing callers from treating discarded mutations as committed state, and it aligns ERL behavior with other unsupported APIs in the codebase.

## Residual Risk
None

## Patch
- Patch file: `036-counter-and-penalty-mutations-are-silently-discarded.patch`
- Effect: changes ERL component and legacy ABI handlers from success-only no-ops to explicit unsupported error returns
- Result: guests no longer receive false negatives that masquerade as valid empty counter or penalty state