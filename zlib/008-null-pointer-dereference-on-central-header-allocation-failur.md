# Null Pointer Dereference on Central Header Allocation Failure

## Classification
- Type: error-handling bug
- Severity: high
- Confidence: certain

## Affected Locations
- `contrib/minizip/zip.c:1401`
- `contrib/minizip/zip.c:1404`

## Summary
`zipOpenNewFileInZip4_64()` allocates `zi->ci.central_header` and immediately writes through that pointer before checking whether allocation succeeded. If `ALLOC` returns `NULL`, the function dereferences a null pointer and crashes the caller process instead of returning `ZIP_INTERNALERROR`.

## Provenance
- Verified by reproduction against the current source snapshot
- Reproducer used a fault-injection harness in `tmp/minizip_null_alloc_poc.c`
- Reference: Swival Security Scanner, https://swival.dev

## Preconditions
- `ALLOC` for `zi->ci.central_header` returns `NULL` during `zipOpenNewFileInZip4_64()`
- Caller reaches zip entry creation with otherwise valid inputs

## Proof
The reproduced path is direct:
- `zipOpenNewFileInZip4_64()` computes `size_centralheader`
- `zi->ci.central_header = (char*)ALLOC((uInt)size_centralheader);`
- The code then calls `zip64local_putValue_inmemory(zi->ci.central_header, ...)` and performs subsequent writes before any null check
- With fault injection forcing the second allocation in this path to fail, execution terminates with `SIGSEGV` immediately after the logged failed allocation
- The snapshot’s vulnerable block is in `contrib/minizip/zip.c:1401` through `contrib/minizip/zip.c:1445`

## Why This Is A Real Bug
This is reachable error-handling code on allocator failure, not a theoretical misuse case. Input length validation does not prevent the condition; it only bounds field sizes. On memory pressure or allocator failure, the library crashes the host process at the point where it should surface a recoverable internal error. That is a concrete availability impact in any application using minizip to create entries.

## Fix Requirement
Check `zi->ci.central_header` immediately after `ALLOC` and return `ZIP_INTERNALERROR` before any writes or helper calls that dereference the pointer.

## Patch Rationale
The patch moves the allocation failure check to immediately follow the `ALLOC` call for `central_header`. This preserves existing behavior on success and restores intended error handling on failure by returning cleanly before touching the buffer.

## Residual Risk
None

## Patch
- Patch file: `008-null-pointer-dereference-on-central-header-allocation-failur.patch`
- Change: add an immediate null check after `zi->ci.central_header` allocation in `contrib/minizip/zip.c`, before `zip64local_putValue_inmemory()` and all subsequent header-buffer writes