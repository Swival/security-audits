# Empty Samples Panic

## Classification

Validation gap; low severity; confidence: certain.

## Affected Locations

`src/crypto/internal/entropy/v1.0.0/entropy.go:158`

## Summary

`RepetitionCountTest` indexes `samples[0]` before validating that `samples` is non-empty. Direct callers that pass `nil` or `[]uint8{}` trigger a runtime panic instead of receiving a controlled return value.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

Caller invokes `RepetitionCountTest` with an empty slice.

## Proof

`RepetitionCountTest(nil)` and `RepetitionCountTest([]uint8{})` both reach the initial `samples[0]` access before any loop or error path. With `len(samples) == 0`, Go raises an out-of-range runtime panic.

The normal `Samples` caller path is guarded by a minimum length check, but `RepetitionCountTest` is directly reachable by internal callers and tests.

## Why This Is A Real Bug

An exported internal-package function accepts caller-provided input but does not validate the empty-slice case before indexing. This creates a deterministic panic and local denial-of-service condition for any direct internal caller that passes empty input.

## Fix Requirement

Return safely before reading `samples[0]` when `len(samples) == 0`.

## Patch Rationale

The patch adds an explicit empty-input guard at the start of `RepetitionCountTest`, preventing the out-of-range index operation while preserving existing behavior for non-empty sample slices.

## Residual Risk

None

## Patch

`040-empty-samples-panic.patch`