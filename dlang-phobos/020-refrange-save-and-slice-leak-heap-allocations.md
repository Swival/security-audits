# RefRange save/slice drops owned saved ranges without destruction

## Classification
- Type: resource lifecycle bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/range/package.d:5000`
- `std/range/package.d:12450`

## Summary
`RefRange.save` and slice operations allocate a saved/sliced range object on the heap, wrap its pointer in `RefRange!S`, and return that wrapper. `RefRange` only stores `R* _range` and had no ownership tracking or destructor path, so dropping the returned wrapper never destroys the heap-emplaced `S`. For saved/sliced range types with elaborate destructors, reachable calls to `.save` or slicing permanently skip required cleanup.

## Provenance
- Verified from the provided reproducer and source inspection in `std/range/package.d`
- Reproduced locally from the described behavior: plain `save` runs the saved object's destructor, while `refRange(...).save` does not
- Scanner source: https://swival.dev

## Preconditions
- Caller invokes `RefRange.save` or slicing on a forward or sliceable range
- The produced saved/sliced type `S` owns resources or otherwise relies on `S.~this()`

## Proof
`RefRange.save` and `RefRange.opSlice` construct `S` in heap storage via `new void[S.sizeof]` and `emplace!S(...)`, then return `RefRange!S(cast(S*) mem.ptr)`. `RefRange` retained only a raw `R* _range`, with no ownership metadata and no destructor at `std/range/package.d:12450`, so the wrapper had no path to run `S.~this()` or release the backing allocation. The reproducer confirms the behavioral gap: direct `base.save` increments the destructor counter, while `std.range.refRange(&base).save` leaves it at zero even after forced GC.

## Why This Is A Real Bug
This is not just a theoretical heap-retention issue. The returned `RefRange!S` becomes the sole owner of the heap-emplaced saved/sliced range object, and dropping that wrapper loses the only reference without invoking its destructor. Any cleanup encoded in `S.~this()`—such as refcount release, handle closure, lock release, or non-GC memory teardown—is skipped. The original title overstates the mechanism as a plain allocation leak, but the underlying resource-lifecycle failure is real and observable.

## Fix Requirement
`RefRange` must represent ownership for heap-emplaced saved/sliced ranges and destroy owned `S` instances when the wrapper is dropped, or avoid heap-emplacing owned saved/sliced objects altogether by storing them by value.

## Patch Rationale
The patch adds an ownership path for heap-backed saved/sliced ranges so `RefRange` can distinguish borrowed pointers from internally-owned ones. On destruction, an owning `RefRange!S` now runs `S.~this()` and releases the associated storage. This preserves existing borrowed-reference behavior while restoring correct lifecycle semantics for `.save` and slicing.

## Residual Risk
None

## Patch
- Patch file: `020-refrange-save-and-slice-leak-heap-allocations.patch`
- Patched area: `std/range/package.d`
- Effect: `RefRange.save` and slice-created wrappers now clean up owned saved/sliced range objects instead of silently dropping them