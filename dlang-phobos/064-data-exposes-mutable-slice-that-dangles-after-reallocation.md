# data() mutable slice can dangle after reallocation

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/container/array.d:625`

## Summary
`Array.data()` returns the live mutable internal slice backing the container. Later mutations such as `reserve()`, growth, `insertBack()`, or `clear()` can reallocate or free that storage, leaving previously returned `T[]` values pointing at detached or freed memory. Those stale writable aliases remain usable and permit writes outside the container's valid storage.

## Provenance
- Verified from source review and reproduced at the API/invariant level in the checked-out codebase
- Scanner: https://swival.dev

## Preconditions
- Caller retains a mutable slice obtained from `data()`
- The array subsequently mutates in a way that reallocates or frees backing storage

## Proof
`Array.data()` exposes `_data._payload` directly as mutable storage. `Payload.reserve()` may replace `_payload` via reallocation or allocate-copy-free logic, and `clear()` resets `_data`, causing prior payload storage to be released through `Payload.~this`. Any earlier `T[]` obtained from `data()` still references the old region. A later write through that stale slice targets memory no longer owned by the container, violating storage validity and enabling corruption of detached or freed memory. This path is reachable entirely through public APIs: `data()`, then `reserve()`, length growth, `insertBack()`, or `clear()`.

## Why This Is A Real Bug
This is not a documentation-only iterator invalidation issue. The API returns a first-class mutable slice, which the type system continues to treat as writable after backing storage changes. Unlike an iterator abstraction, the stale alias can still be indexed and written through directly, creating a concrete use-after-free or detached-write hazard from safe-looking public calls.

## Fix Requirement
Stop exposing mutable internal backing storage through `data()`. The API must return a non-mutable view or another form that cannot outlive storage changes as a writable alias.

## Patch Rationale
The patch changes `data()` to stop returning a mutable alias to `_data._payload`, replacing it with a non-mutable exposure so callers can still inspect contents without acquiring write access to storage whose lifetime is controlled by later container mutations. This removes the stale-write primitive while preserving read access semantics.

## Residual Risk
None

## Patch
- Patch file: `064-data-exposes-mutable-slice-that-dangles-after-reallocation.patch`
- Patched component: `std/container/array.d`
- Effect: removes mutable exposure of internal payload from `Array.data()` so retained views cannot be used to write into reallocated or freed backing storage