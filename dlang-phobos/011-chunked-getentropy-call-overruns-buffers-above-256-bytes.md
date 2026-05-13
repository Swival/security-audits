# Chunked `getentropy` loop uses the full buffer and breaks requests above 256 bytes

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `std/internal/entropy.d:659`

## Summary
On the BSD `getentropy` path, the chunking loop is implemented incorrectly. The code iterates over 256-byte chunks, but each iteration still calls `getentropy(buffer.ptr, buffer.length)` instead of using the current chunk. For any request larger than 256 bytes, the syscall is invoked with an oversized length, which violates the API contract and deterministically fails with `EINVAL` on supported systems.

## Provenance
- Verified from the provided reproducer and source inspection in `std/internal/entropy.d:659`
- Swival Security Scanner: https://swival.dev

## Preconditions
- BSD `getentropy` backend is selected
- Caller requests entropy into a buffer longer than 256 bytes

## Proof
Control flow is:
- public `getEntropy(buffer)`
- `getEntropyImpl`
- `getEntropyViaGetentropy`
- `callGetentropy`

Inside `callGetentropy`, the code loops over `VoidChunks(buffer, 256)` but does not use `chunk.ptr` or `chunk.length` for the syscall. Instead, every iteration passes the original `buffer.ptr` and `buffer.length`.

This means:
- requests of 256 bytes or less succeed normally
- requests above 256 bytes call `getentropy` with an invalid length on the first iteration
- the function returns `readError`
- fallback does not occur under `EntropySource.tryAll`, because `_tryEntropySources` stops on any result other than `unavailable`

A concrete trigger is a BSD caller requesting 257 bytes, e.g. `ubyte[257] buf; getEntropy(buf[]);`, which fails on this path.

## Why This Is A Real Bug
The implementation explicitly intends to satisfy the 256-byte `getentropy` limit by chunking. That invariant is broken because the chunked loop never updates the syscall arguments. The result is a reliable functional failure for valid larger requests on BSD targets using this backend.

This is not a memory overwrite bug: the syscall still receives the original in-bounds pointer and length, and documented oversized-call behavior is failure rather than out-of-bounds writing. The actual impact is denial of service / backend failure for requests above 256 bytes.

## Fix Requirement
Change the syscall invocation inside the chunk loop to use the active chunk:
- pass `chunk.ptr`
- pass `chunk.length`

## Patch Rationale
Using the chunk slice restores the intended contract: each `getentropy` call is bounded to at most 256 bytes and advances through the destination buffer correctly. This preserves existing behavior for small buffers and fixes deterministic failure for larger ones.

## Residual Risk
None

## Patch
- `011-chunked-getentropy-call-overruns-buffers-above-256-bytes.patch` updates `std/internal/entropy.d` so the loop calls `getentropy(chunk.ptr, chunk.length)` instead of reusing the full buffer arguments.