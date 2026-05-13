# Allocator fallback returns previous extra allocator on mismatch

## Classification
- Type: logic error
- Severity: high
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/typed.d:179`
- `std/experimental/allocator/typed.d:152`
- `std/experimental/allocator/typed.d:69`
- Patch: `061-allocator-fallback-returns-more-specific-policy-on-mismatch.patch`

## Summary
The fallback selection loop in `allocatorFor(uint)` returns `extras[i - 1]` as soon as a later policy does not match the requested flags. This premature return can select an earlier neighboring allocator and prevents evaluation from reaching a later exact policy. As reproduced, a request for flag `8` stops at policy `4` and returns policy `1`, violating the documented guarantee that an implemented allocator for a given flag combination is used.

## Provenance
- Verified finding reproduced from the provided report and reproducer summary
- Source under review: `std/experimental/allocator/typed.d`
- Scanner provenance: https://swival.dev

## Preconditions
- At least one extra policy exists
- Requested flags mismatch a later policy during fallback traversal
- A later policy is a better or exact match for the request

## Proof
The reproduced control flow shows:
- Caller-controlled type/flag input reaches `allocatorFor(uint)` via `allocatorFor!T` and `allocatorFor!flags`
- In `std/experimental/allocator/typed.d:179`, the fallback loop executes `static if (!match(choice, flags)) return extras[i - 1];`
- With configured policies `[1, 4, 8]` and a request for flags `8`, the loop encounters `4`, evaluates the mismatch branch, and returns `extras[0]` for policy `1`
- The exact `8` policy is never evaluated
- The reproducer confirms reachable API surface through `type2flags!(immutable(Object)[])()`, so calls such as `allocatorFor!(immutable(Object)[])` can dispatch incorrectly

## Why This Is A Real Bug
The function’s documented behavior in `std/experimental/allocator/typed.d:69` states that when an allocator exists for a given flag combination, it is used. The current loop contradicts that contract by treating a mismatch in one later candidate as grounds to return a prior allocator. This is not a theoretical ordering issue; it causes observable misrouting of allocation and disposal operations to a less appropriate policy even when an exact configured policy exists.

## Fix Requirement
Track the last matching allocator while iterating extras and return that best-known match after traversal. The fallback logic must not return on `!match(choice, flags)`.

## Patch Rationale
The patch in `061-allocator-fallback-returns-more-specific-policy-on-mismatch.patch` changes fallback selection to preserve the most recent valid match and continue scanning for a better or exact policy. This removes the premature mismatch return, restores monotonic selection behavior, and aligns implementation with the module contract.

## Residual Risk
None

## Patch
```diff
diff --git a/std/experimental/allocator/typed.d b/std/experimental/allocator/typed.d
--- a/std/experimental/allocator/typed.d
+++ b/std/experimental/allocator/typed.d
@@
-        foreach (i, choice; extrasFlags)
-        {
-            static if (!match(choice, flags))
-                return extras[i - 1];
-        }
+        typeof(extras[0]) best = extras[0];
+        foreach (i, choice; extrasFlags)
+        {
+            static if (match(choice, flags))
+                best = extras[i];
+        }
+        return best;
```