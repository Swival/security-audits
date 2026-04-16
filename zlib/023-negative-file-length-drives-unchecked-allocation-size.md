# Negative file length drives unchecked allocation size

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `contrib/testzlib/testzlib.c:104`

## Summary
`ReadFileMemory` assigns `ftell(stream)` to `*plFileSize` without rejecting negative results. When `ftell` returns `-1L`, the value flows into `malloc((*plFileSize)+1)` and `fread(ptr, 1, *plFileSize, stream)`, breaking the invariant that file length must be nonnegative before allocation and read sizing.

## Provenance
- Verified from the provided finding and reproduction details
- Reproduced behavior matches the source control/data flow in `contrib/testzlib/testzlib.c`
- Reference: https://swival.dev

## Preconditions
- `ftell(stream)` returns a negative value
- `fopen` succeeds on a stream that does not reliably support seeking or telling

## Proof
- `main` passes `argv[1]` directly to `ReadFileMemory` in `contrib/testzlib/testzlib.c:160`
- `ReadFileMemory` performs `fseek(stream, 0, SEEK_END)` and stores `ftell(stream)` into `*plFileSize` at `contrib/testzlib/testzlib.c:104`
- No `< 0` validation is applied before `malloc((*plFileSize)+1)` and `fread(ptr, 1, *plFileSize, stream)`
- On Windows, special device names can be opened by `fopen`; seek/tell on such streams can fail
- The reproduced pattern showed `ftell == -1`, a tiny allocation, and an immediate ASan heap-buffer-overflow when `fread` copied input into that undersized buffer

## Why This Is A Real Bug
The failing condition is externally triggerable through a user-supplied path passed into `ReadFileMemory`. Once `ftell` returns a negative value, the code uses that invalid signed length as a size operand for allocation and reading. That creates an undersized or otherwise invalid buffer sizing decision before the function can report failure, enabling memory corruption on reachable error paths.

## Fix Requirement
Reject `fseek` and `ftell` failures before using the reported length. Require `*plFileSize >= 0` before allocation and before passing the length to `fread`; otherwise return failure.

## Patch Rationale
The patch in `023-negative-file-length-drives-unchecked-allocation-size.patch` adds error handling for seek/tell failures and blocks negative file lengths from reaching allocation and read operations. This restores the nonnegative-length invariant at the point of use and converts the dangerous path into a clean failure.

## Residual Risk
None

## Patch
- `023-negative-file-length-drives-unchecked-allocation-size.patch` validates `fseek`/`ftell` results in `ReadFileMemory`
- Negative or otherwise invalid lengths now cause early failure instead of reaching `malloc` and `fread`
- The change is narrowly scoped to the vulnerable path in `contrib/testzlib/testzlib.c`