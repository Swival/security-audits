# Failed `reallocate` corrupts scoped allocation metadata

## Classification
- Type: resource lifecycle bug
- Severity: high
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/building_blocks/scoped_allocator.d:119`

## Summary
`ScopedAllocator.reallocate` mutates scope-tracking state before reallocation success is known. When the parent allocator fails `reallocate` while leaving `b` live, the scoped metadata can retain the requested size instead of the original size. Later `deallocateAll` uses that stale size when freeing the still-live allocation, propagating incorrect deallocation metadata to the parent allocator.

## Provenance
- Verified from the supplied reproducer and patch target in `std/experimental/allocator/building_blocks/scoped_allocator.d`
- Reproduced locally with the provided PoC behavior summary
- Scanner reference: https://swival.dev

## Preconditions
- A tracked scoped allocation already exists
- `ScopedAllocator.reallocate` is called on that allocation
- `parent.reallocate(b, s)` fails while leaving `b.ptr` non-null and the original allocation live
- Parent deallocation behavior depends on the exact block size recorded for cleanup

## Proof
The reproduced PoC uses a compliant parent allocator whose `reallocate` always fails without clearing `b`, and whose `deallocate` asserts it receives the original size.
Running:

```sh
ldc2 -I. scoped_realloc_poc.d -of=scoped_realloc_poc && ./scoped_realloc_poc
```

produces an `AssertError: wrong length passed to deallocate` from `scoped_realloc_poc.d:28`, reached through `ScopedAllocator.deallocateAll()`.

Observed behavior:
- allocate 16 bytes under `ScopedAllocator`
- call `scoped.reallocate(b, 32)`
- call returns `false`
- `b.length` remains `16`
- later `deallocateAll` frees using recorded size `32`

This demonstrates that failed `reallocate` leaves scoped tracking inconsistent with the live allocation state, and the bad metadata reaches the parent deallocator.

## Why This Is A Real Bug
This is a concrete lifecycle correctness failure, not a theoretical API ambiguity. The scoped allocator promises to track live allocations for later cleanup. After a failed `reallocate`, cleanup must still describe the original allocation accurately. Instead, the allocator can preserve a mismatched size record and issue a deallocation for the wrong extent. For size-sensitive parent allocators, that causes assertion failure, rejected frees, or incorrect memory release behavior.

## Fix Requirement
On failed `reallocate`, preserve the original tracked node state. The allocator must either:
- defer unlinking or metadata mutation until reallocation succeeds, or
- fully restore the original node and size on failure

## Patch Rationale
The patch in `065-failed-reallocate-drops-allocation-from-scope-tracking.patch` keeps scoped tracking consistent across failed `reallocate` attempts by avoiding permanent state loss or stale-size retention when the parent call does not succeed. This ensures `deallocateAll` later frees the original live block with correct metadata.

## Residual Risk
None

## Patch
- `065-failed-reallocate-drops-allocation-from-scope-tracking.patch` updates `std/experimental/allocator/building_blocks/scoped_allocator.d` so failed `reallocate` no longer corrupts or desynchronizes the tracked allocation record used by scoped cleanup.