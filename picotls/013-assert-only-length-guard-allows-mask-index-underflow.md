# Assert-only length guard allows mask index underflow

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/quiclb-impl.h:125`
- `lib/quiclb-impl.h:135`
- `lib/quiclb-impl.h:147`
- `lib/quiclb-impl.h:150`

## Summary
`picotls_quiclb_transform` trusts `len` after an `assert`-only size check. In release builds with `NDEBUG`, values outside the supported QUIC-LB block range (`7..19`) are not rejected before `masks[len - PTLS_QUICLB_MIN_BLOCK_SIZE]` is computed. For `len < 7`, the subtraction underflows in `size_t`; for `len > 19`, the index is also out of range. The resulting invalid `mask` pointer is dereferenced in later rounds, causing out-of-bounds reads and undefined behavior.

## Provenance
- Verified from the provided finding and reproducer against the committed codebase
- Scanner source: https://swival.dev

## Preconditions
- Release build with assertions disabled
- Caller passes `len` outside `7..19`

## Proof
- `picotls_quiclb_transform` only enforced the valid length range with `assert`.
- In release builds, `const struct quiclb_mask_t *mask = &masks[len - PTLS_QUICLB_MIN_BLOCK_SIZE];` executed without a runtime guard.
- With `len = 0`, `len - PTLS_QUICLB_MIN_BLOCK_SIZE` underflowed as `size_t`, producing a huge array index.
- UBSan reported the out-of-bounds index at `lib/quiclb-impl.h:135`.
- The invalid `mask` pointer was then dereferenced through `mask->l` and `mask->r` in the round calls at `lib/quiclb-impl.h:147`, `lib/quiclb-impl.h:148`, `lib/quiclb-impl.h:149`, and `lib/quiclb-impl.h:150`.
- The same bug class applies to oversized inputs (`len > 19`), which also index past `masks`.

## Why This Is A Real Bug
This is reachable in production because the guard was assertion-only. Assertions are commonly compiled out in release builds, leaving exported cipher code to operate on unchecked caller-controlled lengths. Once the invalid index is computed, the function reads mask data from memory outside the `masks` table and continues transformation rounds with undefined state. That is concrete memory-safety-impacting behavior and can cause process termination under sanitizers or nondeterministic failures in normal builds.

## Fix Requirement
Replace the `assert`-only length validation with a runtime bounds check that executes before indexing `masks`, and return without performing the transform when `len` is outside the supported range.

## Patch Rationale
The patch adds an explicit runtime range check in `picotls_quiclb_transform` before calculating the mask-table index. This prevents both the `size_t` underflow case for `len < 7` and the upper-bound out-of-range case for `len > 19`. Keeping the validation at the function entry preserves existing behavior for valid lengths while ensuring release builds enforce the same safety contract as debug builds.

## Residual Risk
None

## Patch
- Patch file: `013-assert-only-length-guard-allows-mask-index-underflow.patch`
- Change: add a runtime `len` bounds check before `masks[len - PTLS_QUICLB_MIN_BLOCK_SIZE]` in `lib/quiclb-impl.h`
- Effect: invalid lengths no longer reach mask indexing or round processing, eliminating the out-of-bounds read path