# Duration conversion panic on oversized cache metadata

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/component/compute/cache.rs:415`
- `src/component/compute/cache.rs:581`
- `src/wiggle_abi/cache.rs:663`

## Summary
Cache metadata duration values are converted from `u128` nanoseconds to `u64` with `try_into().unwrap()`. If cache metadata contains an age or max-age larger than `u64::MAX` nanoseconds, the conversion panics and crashes the host-side cache API path instead of returning an error.

## Provenance
- Verified by reproduction and patching against the reported code path
- Scanner source: https://swival.dev

## Preconditions
- Cached entry metadata `max_age` exceeds `u64::MAX` nanoseconds, or stored `initial_age_ns` is set to `u64::MAX` and any positive elapsed time accrues before `get_age_ns` is called

## Proof
- `found.meta().max_age()` flows into `get_max_age_ns` in `src/component/compute/cache.rs:415`, where `Duration::as_nanos()` yields `u128` and is narrowed with `try_into().unwrap()`
- Cache insertion accepts `initial_age_ns` and stores it through `src/component/compute/cache.rs:138` into `src/cache/store.rs:345`
- Lookup returns the stored entry through `src/cache.rs:307`, and both age accessors unwrap the same fallible conversion in `src/component/compute/cache.rs:581` and `src/wiggle_abi/cache.rs:663`
- Reproduction used `Duration::from_nanos(u64::MAX)`, then computed age as elapsed time plus initial age; once elapsed time is nonzero, `age().as_nanos() > u64::MAX`, and `as_nanos().try_into().unwrap()` panics with `called Result::unwrap() on an Err value: TryFromIntError(())`

## Why This Is A Real Bug
The panic is reachable through normal cache API usage with attacker-controlled or otherwise untrusted metadata inputs. A caller can insert an entry with maximal `initial_age_ns`, then read its age after any measurable delay and deterministically crash the host process. This is a denial-of-service condition, not a theoretical edge case.

## Fix Requirement
Replace all `u128 -> u64` duration narrowing `unwrap()` calls on cache metadata paths with checked handling that either returns a typed error or saturates to `u64::MAX`, and apply the same policy consistently to both max-age and age accessors.

## Patch Rationale
The patch removes panic-on-conversion behavior from the affected cache metadata accessors and replaces it with explicit checked handling. This preserves API stability while ensuring oversized duration values no longer abort the process when queried.

## Residual Risk
None

## Patch
- `002-duration-conversion-can-panic-on-large-cache-metadata.patch`