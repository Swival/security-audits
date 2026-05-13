# lazyCache stale front cache after popBack

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `std/algorithm/iteration.d:399`

## Summary
`lazyCache` caches `front` in `caches[0]` and marks `frontCached`, but `popBack` only mutates the wrapped source and clears `backCached`. On bidirectional ranges where removing the back changes the current front or empties the range, a later `front()` returns stale cached data that is no longer present in the source.

## Provenance
- Verified from the provided reproducer and code inspection in `std/algorithm/iteration.d:399`
- External reference: https://swival.dev

## Preconditions
- A bidirectional `lazyCache`
- `front()` called before `popBack()`
- Wrapped range semantics permit `popBack()` to change the current `front` or empty the range

## Proof
The reproduced case uses a valid bidirectional range whose current element is derived from the midpoint of `[left, right]`. For that range:
- Base range `front` before `popBack`: `1`
- Base range `front` after `popBack`: `0`
- `lazyCache` `front` before `popBack`: `1`
- `lazyCache` `front` after `popBack`: `1`

This shows `lazyCache` serving the stale cached `front` after the wrapped range changed.

## Why This Is A Real Bug
`lazyCache` is a range adaptor and must preserve observable range semantics. Returning an element that is no longer the current `front`, or no longer exists after the source shrinks, violates that contract. Any consumer relying on `front` after `popBack` can make decisions on invalid data.

## Fix Requirement
`popBack()` must invalidate `frontCached` whenever back-removal may change the front view, and clear stale caches when the wrapped range becomes empty.

## Patch Rationale
The patch updates `lazyCache.popBack` to stop reusing a previously cached `front` across source mutation from the back. This restores consistency between cached state and the wrapped range after `popBack`, preventing stale reads while preserving lazy caching behavior for unchanged states.

## Residual Risk
None

## Patch
- `008-lazycache-returns-stale-front-after-back-pop.patch`