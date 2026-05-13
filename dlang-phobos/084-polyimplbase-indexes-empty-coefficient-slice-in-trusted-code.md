# polyImplBase indexes empty coefficient slice in trusted code

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/math/algebraic.d:576`

## Summary
- `poly(x, A)` relies on an `in` contract to reject empty coefficient slices, but that contract is removed when contracts are disabled.
- With `A.length == 0`, execution reaches trusted helper code that computes `A.length - 1`, underflows to `-1`/`size_t.max`, and immediately reads before the slice.
- This is a trusted out-of-bounds read reachable from caller-controlled input, causing at least process crash and violating internal slice-bounds invariants.

## Provenance
- Verified from the supplied reproducer and patch target in `std/math/algebraic.d`.
- Reproduction and patch prepared from local testing against the reported path.
- Reference: Swival Security Scanner `https://swival.dev`

## Preconditions
- Call `poly(x, A)` with `A.length == 0`.
- Build with contracts disabled, such as release-style configurations where the `in` check is omitted.

## Proof
- `poly` accepts caller-controlled coefficients and only guards emptiness via an `in` contract.
- When contracts are disabled, empty input flows into trusted helper logic.
- In the affected path, `ptrdiff_t i = A.length - 1` evaluates to `-1` for an empty slice.
- The next statement reads `A[i]`, which becomes an access before the slice start.
- Reproduction confirmed:
  - Building a minimal test with `ldc2 -I. -release` and calling `poly(2.0, double[]())` crashes with exit status `139`.
  - Rebuilding with `-release -boundscheck=on` raises `ArrayIndexError` at `std/math/algebraic.d:620`, confirming the computed index is `size_t.max`.
  - Calling `poly(2.0L, immutable(real)[]())` also segfaults; LLDB shows an invalid load from `base - 8`, matching the empty-slice underflow in the real-specialized helper.

## Why This Is A Real Bug
- The invalid access occurs before any effective runtime emptiness guard on the affected release path.
- The buggy read is inside trusted code, so it breaks a core memory-safety invariant rather than merely failing a public precondition cleanly.
- The issue is externally reachable through a normal API with caller-controlled input.
- The observed behavior is a real crash, not a theoretical miscompile or unreachable state.

## Fix Requirement
- Replace the contract-only emptiness check with an explicit runtime `A.length` validation on the public entry path before dispatching to trusted helpers.
- Ensure the check remains active in release builds.

## Patch Rationale
- The patch in `084-polyimplbase-indexes-empty-coefficient-slice-in-trusted-code.patch` moves the empty-slice validation into normal runtime logic ahead of helper dispatch.
- This preserves existing behavior for valid inputs while making the precondition enforceable when contracts are compiled out.
- Guarding at the entry point prevents all known helper variants from receiving an empty coefficient slice and eliminates the underflowing index calculation.

## Residual Risk
- None

## Patch
```diff
diff --git a/std/math/algebraic.d b/std/math/algebraic.d
index 0000000..0000000 100644
--- a/std/math/algebraic.d
+++ b/std/math/algebraic.d
@@ -576,6 +576,9 @@ if (isSomeChar!X || isFloatingPoint!X)
 {
-    in (A.length > 0)
+    if (A.length == 0)
+    {
+        assert(0, "Array of polynomial coefficients cannot be empty");
+    }
     do
     {
         static if (is(typeof(polyImpl(x, A))))
```