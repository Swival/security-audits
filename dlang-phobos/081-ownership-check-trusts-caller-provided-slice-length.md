# Ownership Check Uses Caller-Controlled Length

## Classification
- Type: trust-boundary violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/building_blocks/bucketizer.d:171`

## Summary
`Bucketizer.owns(void[] b)` derives the candidate bucket from the caller-provided `b.length`, then asks only that bucket whether it owns the memory. Because D slices have mutable length, a caller can present a valid allocated pointer with a forged length that maps to a different bucket size class. This causes `owns` to return `no` for memory actually allocated by the `Bucketizer`.

## Provenance
- Verified from the provided finding and reproducer
- Reproduced against the implementation in `std/experimental/allocator/building_blocks/bucketizer.d`
- Reference: https://swival.dev

## Preconditions
- Caller can pass a non-null slice with modified length

## Proof
The reproduced behavior shows the false negative is introduced by `Bucketizer`, not by child allocators:
- `Bucketizer.owns` selects a bucket using `allocatorFor(b.length)` and queries only that allocator.
- Returned slices are length-mutable, so a caller can retain the original pointer and alter the slice length before calling `owns`.
- Child allocators accept pointer-range ownership independently of original request size:
  - `std/experimental/allocator/building_blocks/bitmapped_block.d:1144`
  - `std/experimental/allocator/building_blocks/region.d:605`

Observed reproduction:
```text
goodAllocSize(100)=128
goodAllocSize(200)=256
bucket0 owns actual: Ternary(2)
bucketizer owns forged len 200: Ternary(0)
```

This demonstrates:
- allocation of `100` bytes is placed in the `128`-byte bucket,
- the same pointer, viewed as length `200`, is still owned by the underlying bucket allocator,
- but `Bucketizer.owns` returns `no` because it routes the query to the `256`-byte bucket solely from forged length.

## Why This Is A Real Bug
`owns` is an ownership oracle at a trust boundary. Its result must not depend on untrusted metadata when the implementation can instead validate ownership by pointer. Here, a caller-controlled slice length changes allocator selection and produces a false negative for genuinely owned memory. That can break validation paths, allocator dispatch, and any caller logic that relies on `owns` to determine whether a pointer belongs to this allocator.

## Fix Requirement
Make ownership resolution pointer-based rather than length-based. `Bucketizer.owns` must not trust `b.length` to choose a single bucket. It should probe buckets by pointer, such as iterating all buckets and returning `yes` when any child allocator reports ownership.

## Patch Rationale
The patch in `081-ownership-check-trusts-caller-provided-slice-length.patch` updates `Bucketizer.owns` to stop deriving ownership from the caller-supplied length. Instead, it checks candidate child allocators by pointer ownership, eliminating the false negative caused by forged slice lengths while preserving correct behavior for valid allocations.

## Residual Risk
None

## Patch
- `081-ownership-check-trusts-caller-provided-slice-length.patch` fixes `Bucketizer.owns` in `std/experimental/allocator/building_blocks/bucketizer.d` by removing the length-trusting single-bucket decision and resolving ownership via bucket probing.