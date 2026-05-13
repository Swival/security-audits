# Deallocate Misroutes Forged Slices Across Buckets

## Classification
- Type: resource lifecycle bug
- Severity: high
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/building_blocks/bucketizer.d:184`

## Summary
`Bucketizer.deallocate` chose the target bucket from `b.length` supplied by the caller, then freed `b.ptr` through that derived bucket without verifying that the slice length still matched the original allocation bucket. A caller could forge a non-null slice with the same base pointer but a different length, causing a live allocation to be returned to the wrong bucket allocator. This enabled overlapping live allocations and allocator state corruption.

## Provenance
- Verified from the provided reproducer and patch artifact `080-deallocate-forwards-slices-to-bucket-chosen-by-caller-length.patch`
- Independent finding provenance: Swival Security Scanner, https://swival.dev

## Preconditions
- Caller can pass a non-null slice whose length does not match the original allocation size class

## Proof
The issue is reproducible with `ldc2` against `Bucketizer!(FreeList!(AllocatorList!(Region!Mallocator...),0,unbounded),65,512,64)`:
```text
allocated length=100 ptr=AA2800000
owns original=Ternary(2)
fake length=200 owns(fake)=Ternary(0)
dealloc fake=true
new length=200 ptr=AA2800000
same ptr? true
```

A 100-byte allocation was obtained, then a forged slice `b.ptr[0 .. 200]` was passed to `deallocate`. Because `deallocate` selected the bucket from the forged length, it inserted the still-live 100-byte block into the 200-byte bucket. A subsequent 200-byte allocation returned the exact same pointer while the original 100-byte allocation remained live. Follow-up writes through the 200-byte allocation modified the 100-byte allocation, demonstrating overlapping live allocations.

## Why This Is A Real Bug
`allocate` returns `result.ptr[0 .. bytes]`, so the visible slice length is mutable by direct slicing and may also change through resizing flows. The deallocation path must therefore not trust caller-provided length as ownership metadata. In the vulnerable implementation, deallocation ownership was inferred solely from `b.length`, which is attacker-controlled once the slice escapes. The reproduced behavior shows concrete allocator misuse: wrong-owner free, double allocation of the same region, and memory corruption through aliasing live allocations.

## Fix Requirement
`deallocate` must not free by a bucket selected only from caller-provided slice length. It must instead recover or verify the original allocation owner/size class before forwarding the free, and reject or fail closed on mismatched slices.

## Patch Rationale
The patch in `080-deallocate-forwards-slices-to-bucket-chosen-by-caller-length.patch` addresses the bug by removing blind length-based forwarding and requiring ownership validation before deallocation proceeds. This aligns the free path with the actual allocation origin instead of mutable caller-visible slice metadata, preventing insertion of live blocks into a different bucket and blocking the reproduced overlap primitive.

## Residual Risk
None

## Patch
The fix is contained in `080-deallocate-forwards-slices-to-bucket-chosen-by-caller-length.patch` and hardens `Bucketizer.deallocate` in `std/experimental/allocator/building_blocks/bucketizer.d` so forged slice lengths cannot redirect frees into the wrong bucket allocator.