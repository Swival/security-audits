# Null pointer dereference on central header allocation failure

## Classification
- Type: error-handling bug
- Severity: high
- Confidence: certain

## Affected Locations
- `contrib/minizip/zip.c:1401`
- `contrib/minizip/zip.c:1404`

## Summary
- `zipOpenNewFileInZip4_64()` allocates `zi->ci.central_header` and immediately writes through the pointer before validating the allocation result.
- If `ALLOC` returns `NULL`, the function dereferences a null pointer and crashes instead of returning `ZIP_INTERNALERROR`.

## Provenance
- Verified from the provided finding and reproduced locally with a fault-injection harness.
- Scanner source: https://swival.dev

## Preconditions
- `ALLOC` for `zi->ci.central_header` returns `NULL` during `zipOpenNewFileInZip4_64()`.
- The caller reaches zip entry creation with otherwise valid arguments.

## Proof
- In `contrib/minizip/zip.c:1401`, `zi->ci.central_header = (char*)ALLOC(size_centralheader);` is performed.
- The code then calls `zip64local_putValue_inmemory(zi->ci.central_header, ...)` at `contrib/minizip/zip.c:1404` and performs further writes before checking whether `zi->ci.central_header == NULL`.
- A fault-injection PoC in `tmp/minizip_null_alloc_poc.c` forces the second allocation in this path, the central-header allocation, to fail.
- Running the harness against the unpatched `contrib/minizip/zip.c` and `contrib/minizip/ioapi.c` produces `SIGSEGV` immediately after logging `failing allocation #2`, confirming the null dereference is reachable.

## Why This Is A Real Bug
- The null check exists but is ordered after dereferences, so it provides no protection on the failing path.
- Input length validation does not rule out allocator failure.
- The observed behavior is process termination, not graceful error propagation, which is a concrete reliability and availability issue in library consumers.

## Fix Requirement
- Validate `zi->ci.central_header` immediately after `ALLOC`.
- Return `ZIP_INTERNALERROR` before any use of the buffer when allocation fails.

## Patch Rationale
- The patch moves the null check to directly follow the `ALLOC` call in `zipOpenNewFileInZip4_64()`.
- This preserves existing behavior on success and restores the intended error return on allocation failure without altering surrounding logic.

## Residual Risk
- None

## Patch
- Patched in `008-null-pointer-dereference-on-central-header-allocation-failur.patch`.
- The change adds an early `NULL` check for `zi->ci.central_header` before any `zip64local_putValue_inmemory()` call or buffer write in `contrib/minizip/zip.c`.