# Expand addition overflow in `expand`

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/building_blocks/quantizer.d:102`

## Summary
`expand` added `delta` to `b.length` before validating that the addition fit in `size_t`. When the sum wrapped, `needed` became smaller than the original buffer length, allowing the in-place fast path to succeed and reslice the buffer to a shorter length on a reported expansion success.

## Provenance
- Verified from the provided reproducer and source inspection
- Reference: Swival Security Scanner - https://swival.dev

## Preconditions
- An existing buffer is passed to `expand`
- Caller-controlled `delta` satisfies `delta > size_t.max - b.length`

## Proof
The reproduced case showed `expand` succeeding while shrinking the buffer:
- initial length was `42`
- `delta` was `18446744073709551615`
- the call returned `ok=true` and the resulting length was `41`

This matches the code path in `std/experimental/allocator/building_blocks/quantizer.d:102`, where `needed = b.length + delta` was computed before any overflow guard. After wraparound, later quantization and equality checks could still pass, and the function resliced `b` to wrapped `needed` at the in-place success path.

## Why This Is A Real Bug
A successful `expand` must not reduce the slice length. Here, overflow turned a growth request into a shrink while still returning success, violating the allocator contract and making callers believe capacity growth occurred. That can corrupt higher-level sizing logic that relies on `expand` success implying monotonic length increase.

## Fix Requirement
Reject expansion when `delta` cannot be added to `b.length` without overflowing `size_t`, before computing `needed`.

## Patch Rationale
The patch adds a pre-addition bound check equivalent to `delta <= size_t.max - b.length`. If the addition would overflow, `expand` returns failure immediately. This preserves the documented invariant that successful expansion represents a real non-wrapping growth request and prevents the wrapped-length fast path from being reached.

## Residual Risk
None

## Patch
Patched in `082-expand-size-addition-can-wrap-before-quantization.patch` by adding an overflow guard in `std/experimental/allocator/building_blocks/quantizer.d` before `needed` is computed in `expand`.