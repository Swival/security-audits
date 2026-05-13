# Expand overflow misroutes segregator allocator

## Classification
- Type: logic error
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/building_blocks/segregator.d:146`

## Summary
`Segregator.expand(ref void[] b, size_t delta)` routes by evaluating `b.length + delta <= threshold`. Because both operands are `size_t`, the addition can overflow before the comparison. Under the reproduced precondition, a block that already belongs to the large allocator can be incorrectly dispatched to `_small.expand`, breaking the segregator's size-based routing invariant.

## Provenance
- Verified from the supplied finding, local reproduction notes, and the patch artifact `079-expand-threshold-check-can-overflow-and-misroute-allocator.patch`
- Scanner reference: https://swival.dev

## Preconditions
- `expand` is called with `delta > size_t.max - b.length`

## Proof
- The public API `expand(ref void[] b, size_t delta)` accepts caller-controlled `delta`.
- In `std/experimental/allocator/building_blocks/segregator.d:146`, dispatch used `if (b.length + delta <= threshold)`.
- With `size_t` arithmetic, `b.length + delta` wraps on overflow, so the comparison can become true for a large-side block.
- Reproduction 1 showed misrouting directly: under `Segregator!(10, ...)`, a block of length `11` with `delta = size_t.max - 5` yielded `ok=1 small=1 large=0 newlen=5`, proving `_small.expand` was selected.
- Reproduction 2 showed concrete invariant failure: a real large-side allocation from `s.allocate(11)` followed by the same `delta` caused `Segregator.expand` to call the small allocator, which asserted `"wrong allocator received block"`.

## Why This Is A Real Bug
The segregator's correctness depends on routing each block back to the allocator that owns its size class. Overflow in the threshold check violates that invariant on a reachable public path. The reproduced assertion demonstrates this is not a theoretical arithmetic issue; it can send a valid large-side allocation into the wrong allocator implementation and trigger runtime failure.

## Fix Requirement
Replace the overflow-prone sum comparison with an overflow-safe check that preserves the original routing rule, e.g. only consider the small path when `b.length <= threshold` and `delta <= threshold - b.length`.

## Patch Rationale
The patch in `079-expand-threshold-check-can-overflow-and-misroute-allocator.patch` removes the wrapping addition from dispatch. By guarding on the current block size and comparing `delta` against the remaining threshold headroom, it preserves small-path behavior for valid non-overflowing cases while preventing large-side blocks from being misrouted after arithmetic wraparound.

## Residual Risk
None

## Patch
```diff
diff --git a/std/experimental/allocator/building_blocks/segregator.d b/std/experimental/allocator/building_blocks/segregator.d
--- a/std/experimental/allocator/building_blocks/segregator.d
+++ b/std/experimental/allocator/building_blocks/segregator.d
@@ -146,7 +146,8 @@
     bool expand(ref void[] b, size_t delta)
     {
-        if (b.length + delta <= threshold)
+        // Avoid overflow when deciding whether the expanded block stays small.
+        if (b.length <= threshold && delta <= threshold - b.length)
             return _small.expand(b, delta);
         return _large.expand(b, delta);
     }
```