# Reallocate integer overflow shrinks backing request

## Classification
- Type: vulnerability
- Severity: high
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/building_blocks/affix_allocator.d:120`
- `std/experimental/allocator/building_blocks/affix_allocator.d:219`

## Summary
`AffixAllocator.reallocate` trusted `actualAllocationSize(s)` without guarding its internal size arithmetic. A caller-controlled large `s` could wrap during prefix/suffix accounting, causing `parent.reallocate` to receive a much smaller size than required. On success, the code then restored the returned slice length to the original large `s`, producing a slice that exceeded the backing allocation.

## Provenance
- Verified from the provided reproducer and code inspection in `std/experimental/allocator/building_blocks/affix_allocator.d`
- Reproduced against committed code using `AffixAllocator!(Mallocator, size_t)` and a wrapping target size
- Reference: https://swival.dev

## Preconditions
- Caller can invoke `reallocate` with a very large requested size

## Proof
The vulnerable path is:
- `reallocate` forwards caller-controlled `s` into `actualAllocationSize(s)` at `std/experimental/allocator/building_blocks/affix_allocator.d:219`
- `actualAllocationSize` adds prefix size, optional alignment padding, and suffix size with no overflow check at `std/experimental/allocator/building_blocks/affix_allocator.d:120`

With `AffixAllocator!(Mallocator, size_t)`:
```d
alias A = AffixAllocator!(Mallocator, size_t);
auto a = A.instance;
void[] b = a.allocate(16);
immutable target = size_t.max - size_t.sizeof + 1;
auto ok = a.reallocate(b, target);
```

Observed runtime result:
- before: valid pointer, `len=16`
- after: `ok=true ptr=8 len=18446744073709551608`

This demonstrates that the computed backing size wrapped to `0`, `Mallocator.reallocate` accepted that wrapped size as authoritative, and the returned slice was then reset to the attacker-controlled large length. The resulting slice points past freed or undersized storage, enabling immediate out-of-bounds access.

## Why This Is A Real Bug
This is a concrete memory-safety failure, not a theoretical arithmetic issue. The reproduced execution shows a successful `reallocate` returning a slice with a massive logical length after the backing request wrapped to `0`. Any subsequent access through that slice operates outside the real allocation and can trigger out-of-bounds read/write or use-after-free style corruption. The bug is directly reachable from a public allocator API with attacker-controlled size input.

## Fix Requirement
Reject `reallocate` requests when affix size computation overflows. The backing allocation size must only be passed to `parent.reallocate` if prefix, alignment, and suffix accounting is proven not to wrap.

## Patch Rationale
The patch adds overflow validation to the affix size computation path and makes `reallocate` fail instead of issuing a wrapped backing request. This preserves allocator invariants: a successful `reallocate` now only returns a slice whose length is representable within the actual parent allocation after affix overhead is included.

## Residual Risk
None

## Patch
Patched in `057-reallocate-integer-overflow-shrinks-backing-request.patch`.