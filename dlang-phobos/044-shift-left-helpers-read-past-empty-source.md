# Shift-left helpers read past empty source

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `std/internal/math/biguintx86.d:255`
- `std/internal/math/biguintx86.d:257`
- `std/internal/math/biguintx86.d:99`

## Summary
`multibyteShlNoMMX` can read one word before `src.ptr` when called with `dest.length == 0`. The function loads from the source based on `dest.length` before any nonempty-length guard, so an empty destination slice causes an immediate out-of-bounds read. Although the reported `multibyteSquare` path is not reachable, the helper is `public` and `@safe`, making the bug directly reachable from safe client code on x86 inline-asm builds.

## Provenance
- Reproduced from the verified report and source review
- Scanner source: [Swival Security Scanner](https://swival.dev)

## Preconditions
- `dest.length == 0` when calling `multibyteShlNoMMX`
- Build targets x86 with `version(D_InlineAsm_X86)` enabled
- Caller can invoke the public helper from safe code

## Proof
At `std/internal/math/biguintx86.d:255`, the function derives the effective index from `dest.length` and performs the first source load before any empty-length check. With `dest.length == 0`, the computed address becomes `src.ptr - 4`, i.e. `src[-1]` for a 32-bit limb. This violates the slice bounds invariant immediately on entry. Reproduction confirmed that the previously claimed `multibyteSquare` call path is not reachable because its slice length is always at least 2, but the helper itself remains externally callable and vulnerable.

## Why This Is A Real Bug
The function is declared `public` and `@safe`, so callers are entitled to pass valid empty slices without triggering memory unsafety. Reading `src[-1]` from safe code is undefined behavior, can disclose adjacent memory, and may fault depending on allocator layout. The bug is therefore a real safety contract violation independent of the incorrect original reachability claim through `multibyteSquare`.

## Fix Requirement
Return `0` immediately when `dest.length == 0`, before the first source load or index-dependent assembly path executes.

## Patch Rationale
The patch adds an early empty-length fast path at function entry in `std/internal/math/biguintx86.d`, ensuring no source access occurs for zero-length slices. This preserves existing behavior for all nonempty inputs while restoring the `@safe` slice invariant for the public helper. The change is minimal, local, and exactly matches the failing precondition.

## Residual Risk
None

## Patch
- Patch file: `044-shift-left-helpers-read-past-empty-source.patch`
- Change: add an early `dest.length == 0` return in `multibyteShlNoMMX` before any assembly reads from `src`
- Result: zero-length calls no longer read `src[-1]`; nonempty behavior remains unchanged