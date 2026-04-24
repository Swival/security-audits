# Age conversion panic on oversized cache metadata

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/component/compute/cache.rs:432`
- `src/wiggle_abi/cache.rs:656`

## Summary
`HostEntry::get_age_ns` converts `found.meta().age().as_nanos()` from `u128` to `u64` with `.try_into().unwrap()`. When cache metadata age exceeds `u64::MAX` nanoseconds, the conversion fails and panics the host instead of returning a controlled result. The same unchecked conversion exists in the legacy ABI entrypoint.

## Provenance
- Verified from the provided finding and reproducer against the codebase
- Source-guided reproduction confirms a reachable panic path through transactional cache lookup followed by age retrieval
- Reference: https://swival.dev

## Preconditions
- A found cache entry has metadata age greater than `u64::MAX` nanoseconds
- The entry is reachable via transactional lookup, including stale-yet-usable entries

## Proof
- In `src/component/compute/cache.rs:432`, `get_age_ns` executes `found.meta().age().as_nanos().try_into().unwrap()`
- `as_nanos()` returns `u128`; values above `u64::MAX` make `try_into()` return `Err`
- `.unwrap()` panics, terminating the host call instead of surfacing an error
- Normal `lookup()` does not practically expose such entries because fresh-entry checks bound usable age by a `u64`-sized `max_age`, but `transaction_lookup()` can return stale entries and still expose the panic path
- The same crash condition exists in `src/wiggle_abi/cache.rs:656`

## Why This Is A Real Bug
The panic is reachable from exported cache-entry APIs on a source-supported path, so malformed or extreme metadata can crash request handling. This violates expected error isolation for cache reads and creates an externally triggerable denial-of-service condition in transactional flows.

## Fix Requirement
Replace the unchecked `u128` to `u64` conversion with bounded handling. The implementation must avoid panicking and should either return a typed error or saturate the age to `u64::MAX` consistently in both the component and legacy ABI paths.

## Patch Rationale
The patch removes `.unwrap()` from both age accessors and applies safe bounded conversion, preserving API behavior while eliminating host panics on oversized metadata. Fixing both bindings is necessary because the same logic is duplicated and both are reachable.

## Residual Risk
None

## Patch
Patched in `003-age-conversion-can-panic-on-large-cache-metadata.patch`.