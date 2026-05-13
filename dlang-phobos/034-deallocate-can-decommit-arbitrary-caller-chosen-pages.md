# Deallocate can decommit arbitrary caller-chosen pages

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/building_blocks/ascending_page_allocator.d:12`

## Summary
`deallocate` accepted arbitrary caller-supplied `void[]` values and used `buf.ptr` and a page-rounded size directly in OS decommit/remap calls. Because it did not verify allocator ownership or page alignment, a caller could target unrelated mapped pages and cause them to be decommitted or remapped.

## Provenance
- Verified from supplied source and reproducer against the public API
- Reference: https://swival.dev

## Preconditions
- Caller can invoke `deallocate` with arbitrary `void[]`
- Target address is page-aligned and mapped for the demonstrated POSIX remap path

## Proof
The reproduced case forged a `void[]` pointing at an unrelated anonymous mapping and passed it to `deallocate`. The allocator then issued the OS-level remap/decommit against that foreign address rather than allocator-owned pages. Observed output:

```text
before=65 deallocate=1 victim=0x1008b4000
mprotect_after=0
after=0
```

This shows the victim page originally contained `65` (`'A'`), `deallocate` succeeded, and after restoring access the page read back as `0`, proving the original mapping contents were destroyed outside allocator ownership.

## Why This Is A Real Bug
This is a direct ownership-boundary violation in a public deallocation path. The allocator reserves a specific page range during construction, but `deallocate` did not require the supplied slice to be fully contained in that range or page-aligned before invoking `mmap(... MAP_FIXED ...)` or `VirtualFree(... MEM_DECOMMIT)`. On reproduced input, this allowed destructive modification of arbitrary in-process mappings, causing integrity and availability impact.

## Fix Requirement
Reject any `deallocate` request unless the full buffer is allocator-owned and both base and size satisfy the page-granularity requirements before making any OS decommit/remap call.

## Patch Rationale
The patch adds strict validation in `ascending_page_allocator.d` so `deallocate` only proceeds for buffers entirely within the allocator’s reserved region and aligned to whole pages. This closes the forged-slice path that let caller-controlled addresses reach `MAP_FIXED` or `MEM_DECOMMIT`.

## Residual Risk
None

## Patch
- `034-deallocate-can-decommit-arbitrary-caller-chosen-pages.patch`