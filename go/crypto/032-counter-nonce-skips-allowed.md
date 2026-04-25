# Counter Nonce Skips Allowed

## Classification

Invariant violation. Severity: medium. Confidence: certain.

## Affected Locations

`src/crypto/internal/fips140/aes/gcm/gcm_nonces.go:132`

## Summary

FIPS AES-GCM deterministic counter nonce enforcement allowed callers to skip counter values. The implementation rejected only counters lower than `g.next`, so a sequence such as `0, 2` was accepted even though the documented invariant requires each subsequent counter to increment by exactly one.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- FIPS mode is enabled.
- Caller supplies deterministic counter nonces to `Seal`.
- Caller uses the same deterministic nonce prefix while advancing the counter non-sequentially.

## Proof

After a first `Seal` with counter `0`, the implementation sets `g.next = 1`.

A second `Seal` with counter `2` passes the old check because:

```go
counter < g.next
```

evaluates as:

```go
2 < 1 == false
```

The call then advances `g.next` to `3` and proceeds to approved encryption.

The existing test behavior also encoded this gap by accepting counters `0`, `1`, and `100`, thereby allowing skipped counters `2..99`.

## Why This Is A Real Bug

The deterministic counter nonce contract requires each subsequent call to increment the counter by exactly one. Accepting `counter > g.next` violates that invariant and allows a non-conforming deterministic nonce sequence to be treated as FIPS-approved.

This does not by itself demonstrate nonce reuse, but it does permit approved operation outside the required sequencing rule.

## Fix Requirement

Require:

```go
counter == g.next
```

before advancing the expected counter.

Preserve the existing `math.MaxUint64` exhaustion protection.

## Patch Rationale

The patch changes the monotonic lower-bound check into an exact-sequence check. This rejects both reused counters and skipped counters, matching the documented deterministic counter requirement.

The exhaustion guard remains necessary because a valid counter equal to `math.MaxUint64` cannot be advanced safely.

## Residual Risk

None

## Patch

`032-counter-nonce-skips-allowed.patch`