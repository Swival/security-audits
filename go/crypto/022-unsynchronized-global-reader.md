# Unsynchronized Global Reader

## Classification

Race condition. Severity: medium. Confidence: certain.

## Affected Locations

`src/crypto/internal/fips140/drbg/rand.go:40`

## Summary

`testingReader` is a package-global interface value accessed by both `SetTestingReader` and `Read` without synchronization. Concurrent calls can race when one goroutine updates the testing reader while another goroutine performs random reads through `crypto/rand.Read`.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

`SetTestingReader` and `Read` are called concurrently.

## Proof

`SetTestingReader` assigns the global `testingReader`. `Read` checks `testingReader != nil` and then calls `testingReader.Read` without a mutex or atomic access.

The reachable call paths are:

- Test override path: `testing/cryptotest.SetGlobalRandom` calls the internal random override, which forwards to `drbg.SetTestingReader`.
- Cleanup path: `testing/cryptotest` cleanup calls the same override with `nil`.
- Read path: public `crypto/rand.Read` reaches `drbg.Read`.

A non-parallel test can still create goroutines. If one goroutine is using `crypto/rand.Read` while another calls `SetGlobalRandom` or while cleanup restores the reader to `nil`, the global interface value is read and written concurrently.

## Why This Is A Real Bug

Go requires shared memory accessed by multiple goroutines to be synchronized when at least one access is a write. The global `testingReader` interface value is written by `SetTestingReader` and read by `Read` without synchronization, producing a real data race.

The race is not only theoretical: the `if testingReader != nil` check and the later `testingReader.Read` call can observe different values because the variable is reloaded without protection.

## Fix Requirement

Guard all reads and writes of `testingReader` with synchronization, such as a mutex or `atomic.Value`. `Read` must use a stable local snapshot of the selected reader before invoking `Read`.

## Patch Rationale

The patch in `022-unsynchronized-global-reader.patch` synchronizes access to the global testing reader. This removes the unsynchronized read/write pair while preserving existing behavior: when a testing reader is configured, `Read` uses it; otherwise, `Read` falls back to the normal DRBG path.

Using a synchronized snapshot also prevents the nil-check and method-call inconsistency.

## Residual Risk

None

## Patch

`022-unsynchronized-global-reader.patch`