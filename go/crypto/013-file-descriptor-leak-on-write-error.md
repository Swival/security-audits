# File descriptor leak on write error

## Classification

Resource lifecycle bug. Severity: low. Confidence: certain.

## Affected Locations

`src/crypto/internal/fips140test/entropy_test.go:62`

## Summary

A test-created file descriptor can remain open when a write to the restart samples file fails. The file is opened with `os.Create`, but `f.Close()` is only called after the write loop, so `t.Fatalf` on a write error bypasses the close.

## Provenance

Verified from the supplied finding and reproducer. Scanner provenance: https://swival.dev

## Preconditions

`-entropy-samples` is set and `f.Write` returns an error after `os.Create(restartSamplesName)` succeeds.

## Proof

`src/crypto/internal/fips140test/entropy_test.go:62` creates the restart samples file with `os.Create(restartSamplesName)`. The descriptor `f` is then used in the restart sample write loop. If any `f.Write(restartSamples[i][:])` fails, execution calls `t.Fatalf` immediately and does not reach the later explicit `f.Close()`. The open file descriptor is therefore leaked on that error path.

This path is reachable through normal write failures after successful create, including `ENOSPC`, quota exhaustion, `EIO`, or filesystem/FUSE behavior that permits create but fails later writes.

## Why This Is A Real Bug

The code has a reachable control-flow path where ownership of an opened `*os.File` is not released. `t.Fatalf` terminates the test goroutine via `runtime.Goexit`, so code after the failing write is skipped unless cleanup is deferred. The impact is limited to a leaked descriptor until finalization or process exit, but the resource lifecycle is still incorrect and close-time cleanup/error handling is skipped.

## Fix Requirement

Call `defer f.Close()` immediately after successful `os.Create(restartSamplesName)`, before entering the write loop.

## Patch Rationale

Deferring `f.Close()` immediately after successful creation binds the descriptor lifetime to the surrounding test scope. This ensures the file is closed on all subsequent exits, including `t.Fatalf` from write errors, while preserving the existing explicit close/error check on the normal path if retained or adjusted by the patch.

## Residual Risk

None

## Patch

`013-file-descriptor-leak-on-write-error.patch`