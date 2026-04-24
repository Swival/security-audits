# Rate-limit checks never report a hit

## Classification
- Type: vulnerability
- Severity: high
- Confidence: certain

## Affected Locations
- `src/component/erl.rs:11`

## Summary
- `check_rate` accepts all rate-limit parameters but ignores them and unconditionally returns `Ok(false)` in `src/component/erl.rs:11`.
- Any caller that relies on `true` to indicate a rate-limit hit or penalty condition can never observe enforcement while running under Viceroy.

## Provenance
- Verified by reproduction against the local fixture and call path described in the reproducer summary.
- Source: Swival Security Scanner, https://swival.dev

## Preconditions
- Caller relies on `check_rate` to enforce any rate limit.

## Proof
- `check_rate` is invoked by the exported adapter path and reachable from guest code, including the fixture at `test-fixtures/src/bin/edge-rate-limiting.rs:14`.
- The implementation in `src/component/erl.rs:11` ignores `_entry`, `_delta`, `_window`, `_limit`, `_pb`, and `_ttl`, then returns `Ok(false)` unconditionally.
- The fixture currently asserts `false` at `test-fixtures/src/bin/edge-rate-limiting.rs:17`, confirming the stubbed behavior.
- As a result, every invocation reports “not rate limited,” so any blocking or penalty logic keyed on a `true` result is unreachable.

## Why This Is A Real Bug
- The API contract requires `check_rate` to reflect whether the configured threshold was exceeded.
- Returning `false` for all inputs defeats rate-limit and penalty-box decision points, creating a deterministic enforcement bypass in the emulator.
- This is security-relevant because Viceroy-based testing cannot validate rate-limiting behavior and will falsely present protected flows as non-blocking.

## Fix Requirement
- Implement actual limit evaluation in `check_rate`.
- Consume the provided inputs and return `true` when usage exceeds the configured threshold, including any applicable penalty-box behavior.

## Patch Rationale
- `035-rate-limit-checks-never-report-a-hit.patch` replaces the unconditional `Ok(false)` stub with real rate-limit evaluation so callers can observe hits when configured limits are exceeded.
- The patch aligns Viceroy behavior with the API contract and restores testability of rate-limit enforcement paths.

## Residual Risk
- None

## Patch
- `035-rate-limit-checks-never-report-a-hit.patch`