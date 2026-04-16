# Negative `ftell` result causes undersized allocation and overflow

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `contrib/testzlib/testzlib.c:104`
- `contrib/testzlib/testzlib.c:103`
- `contrib/testzlib/testzlib.c:106`

## Summary
`ReadFileMemory` stores the `ftell(stream)` result into `*plFileSize` and uses it for allocation and `fread` without rejecting negative values. When `ftell` returns `-1L`, the code computes `malloc((*plFileSize)+1)` and then calls `fread(ptr, 1, *plFileSize, stream)`, breaking the invariant that file length must be nonnegative and enabling an undersized allocation followed by out-of-bounds write.

## Provenance
- Verified reproduced finding from local analysis and reproducer summary
- Reference scanner: https://swival.dev

## Preconditions
- `ftell(stream)` returns a negative value
- `fopen` succeeds on a stream that does not provide a valid seekable file length

## Proof
At `contrib/testzlib/testzlib.c:104`, `ReadFileMemory` assigns `ftell(stream)` directly to `*plFileSize` with no `< 0` validation. The function then uses that value in allocation and read sizing at `contrib/testzlib/testzlib.c:106`. If `ftell` returns `-1L`, `malloc((*plFileSize)+1)` becomes `malloc(0)` or another undersized request after arithmetic on the signed length, while `fread(ptr, 1, *plFileSize, stream)` converts the negative length to a large `size_t`. The reproduced FIFO-based harness showed this exact pattern causing an AddressSanitizer heap-buffer-overflow when 5 bytes were read into a 1-byte allocation. The committed source is reachable from `main`, which passes `argv[1]` directly into `ReadFileMemory` at `contrib/testzlib/testzlib.c:160`.

## Why This Is A Real Bug
The failure mode is not theoretical: `ftell` can return `-1L` on non-seekable inputs or error conditions while `fopen` still succeeds. That negative length is immediately trusted as a valid file size and reused across allocation and read operations. The resulting size mismatch creates memory corruption before the function can safely report failure.

## Fix Requirement
Reject failed `fseek` and negative `ftell` results before any allocation or read. Return failure immediately when file length cannot be established as a nonnegative value.

## Patch Rationale
The patch in `023-negative-file-length-drives-unchecked-allocation-size.patch` adds explicit error handling for `fseek`/`ftell` failure paths and refuses negative file lengths before computing allocation size or calling `fread`. This enforces the file-size nonnegative invariant at the only point where the size is derived.

## Residual Risk
None

## Patch
- `023-negative-file-length-drives-unchecked-allocation-size.patch` adds validation in `ReadFileMemory` so failed `fseek`/`ftell` calls return failure before allocation and read sizing occur.
- The change is minimal and localized to `contrib/testzlib/testzlib.c`, preserving existing behavior for valid seekable files while blocking the reproduced overflow path.