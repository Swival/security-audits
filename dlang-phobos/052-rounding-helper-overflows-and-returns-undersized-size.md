# Rounding helper overflows to undersized allocation size

## Classification
- Type: logic error
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/common.d:145`

## Summary
`roundUpToMultipleOf` computes `rem ? s + base - rem : s` with no overflow guard beyond `assert(base)`. For `size_t` inputs near `size_t.max`, that addition wraps modulo `size_t` and can return a value smaller than the requested size. `goodAllocSize` uses this helper, so allocator size rounding can become undersized instead of monotonic.

## Provenance
- Verified by local reproduction against committed code and patched in `052-rounding-helper-overflows-and-returns-undersized-size.patch`
- Scanner provenance: https://swival.dev

## Preconditions
- `s` is a large `size_t` value near `size_t.max`
- `base` is nonzero
- `s % base != 0`

## Proof
A minimal reproduction using `AscendingPageAllocator` reached the buggy helper through `goodAllocSize` and then `allocate`:

```d
import std.stdio;
import std.experimental.allocator.building_blocks.ascending_page_allocator;
import core.memory : pageSize;

void main() {
    auto a = AscendingPageAllocator(pageSize * 2);
    size_t n = size_t.max - 1;
    writeln("goodSize=", a.goodAllocSize(n));
    auto b = a.allocate(n);
    writeln("ptr=", cast(void*) b.ptr, " len=", b.length);
}
```

Observed output on committed code with LDC:

```text
pageSize=16384 n=18446744073709551614 goodSize=0
b.ptr=101038000 len=18446744073709551614
```

This demonstrates integer wrap in the rounding path: `goodAllocSize(size_t.max - 1)` returns `0`, which is smaller than the requested size and invalid as an allocation rounding result.

## Why This Is A Real Bug
The helper is intended to round sizes up to the next multiple, which must never produce a result below the original request. Returning `0` for a near-maximum request violates that contract and propagates a malformed size through allocator logic. The issue is not theoretical; it is reachable in `AscendingPageAllocator` and was reproduced through public allocator APIs.

## Fix Requirement
Guard the addition in `roundUpToMultipleOf` so overflow cannot wrap, and enforce the postcondition that any rounded result is `>= s`. On overflow, reject the operation or saturate in a defined way rather than returning a wrapped value.

## Patch Rationale
The patch adds an overflow check before `s + base - rem` and enforces monotonicity with an assertion on the computed result. This matches the existing defensive pattern already present in `roundUpToAlignment`, prevents wraparound, and stops undersized rounded sizes from reaching allocator callers.

## Residual Risk
None

## Patch
`052-rounding-helper-overflows-and-returns-undersized-size.patch`