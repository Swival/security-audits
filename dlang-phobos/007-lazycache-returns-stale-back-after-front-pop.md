# lazyCache stale `back` after `popFront`

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `std/algorithm/iteration.d:392`

## Summary
`lazyCache` caches `back` for bidirectional ranges, but `popFront` mutates the underlying source without invalidating that cached tail value. After `back()` is called once, a later `popFront()` can make `LazyCache.back()` return stale data instead of the current `source.back`, violating cache/source consistency and producing incorrect iteration results through the public API.

## Provenance
- Verified from the supplied reproducer and source inspection
- Reference: https://swival.dev

## Preconditions
- A bidirectional range is wrapped with `lazyCache`
- `back()` is called first so `caches[1]` is populated
- A subsequent `popFront()` changes the wrapped range's last remaining element

## Proof
The reproduced path is:
1. Wrap a bidirectional source range with `lazyCache`
2. Call `back()` to populate `caches[1]` and set `backCached`
3. Call `popFront()`
4. Call `back()` again

In `LazyCache.back`, `caches[1]` stores `source.back` and `backCached` is set. In bidirectional `LazyCache.popFront`, the implementation advances `source` and clears only `frontCached`. It does not clear `backCached`. If the source range's tail changes across `popFront()`, the second `back()` returns the stale cached value rather than the updated `source.back`.

The reproducer used a custom bidirectional range where raw behavior was `3 -> 4` for `back`, while `lazyCache` produced `3 -> 3`, confirming stale cache reuse.

## Why This Is A Real Bug
This is a correctness bug in reachable public API behavior, not a theoretical edge case. `lazyCache` promises deferred caching of the wrapped range's elements, but after mutation it can expose values no longer present in the source. That breaks the expected invariant that cached observations remain consistent with the current wrapped range state and can mislead any consumer relying on `back()` after front advancement.

## Fix Requirement
Invalidate the cached tail when bidirectional `LazyCache.popFront` mutates the source, so later `back()` recomputes from the current `source.back`.

## Patch Rationale
Clearing `backCached` in bidirectional `popFront` is the minimal safe fix. It preserves existing lazy behavior, avoids stale reuse after source mutation, and directly restores cache/source consistency without changing the external API or broader iteration semantics.

## Residual Risk
None

## Patch
- Patch file: `007-lazycache-returns-stale-back-after-front-pop.patch`
- Change: update bidirectional `LazyCache.popFront` in `std/algorithm/iteration.d` to invalidate the cached `back` after advancing the source