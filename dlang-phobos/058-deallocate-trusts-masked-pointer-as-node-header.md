# Deallocate trusts masked pointer as node header

## Classification
- Type: trust-boundary violation
- Severity: high
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/building_blocks/aligned_block_list.d:119`

## Summary
`AlignedBlockList.deallocate` masks the caller-supplied pointer down to an aligned base, casts that address to `AlignedBlockNode*`, immediately reads `node.bAlloc`, and forwards the block for deallocation without first proving the block belongs to a tracked node. A non-null foreign pointer is therefore trusted as allocator metadata, enabling unchecked dereference of unrelated memory and a reproducible crash.

## Provenance
- Verified from the supplied finding and reproducer details
- Reproduced by building and running a PoC against the affected allocator path
- Reference: https://swival.dev

## Preconditions
- Caller can pass a non-null unowned pointer to `deallocate`

## Proof
- `std/experimental/allocator/building_blocks/aligned_block_list.d:119` computes an aligned base from `b.ptr` using `& ~(theAlignment - 1)`, casts it to `AlignedBlockNode*`, then reads `node.bAlloc` and calls `node.bAlloc.deallocate(b)`.
- The function does not first call `owns` and does not independently validate list membership or node ownership before dereferencing `node`.
- The reproducer instantiated `AlignedBlockList!(BitmappedBlock!32, AscendingPageAllocator*, 4096)`, `mmap`'d a zero-filled page not owned by the allocator, forged a slice from the interior of that page, and passed it to `deallocate`.
- The call crashed along `AlignedBlockList.deallocate -> BitmappedBlock.deallocate` with `ArrayIndexError` in `std/experimental/allocator/building_blocks/bitmapped_block.d(842)`, showing that foreign memory was treated as allocator state before failure.

## Why This Is A Real Bug
`deallocate` is a trust boundary: it accepts caller-controlled memory and must reject foreign pointers before interpreting adjacent memory as allocator metadata. Here, the implementation derives a header address from attacker-controlled input and dereferences it immediately. The observed crash confirms denial of service. Because the dereferenced header controls which backing allocator receives the block, different page contents can also steer unchecked reads and writes through forged metadata, making this more than a defensive-programming concern.

## Fix Requirement
Ensure `deallocate` verifies that the block belongs to a tracked `AlignedBlockNode` before dereferencing `node.bAlloc` or forwarding deallocation. Rejection must occur before any metadata access based on the masked pointer.

## Patch Rationale
The patch adds an ownership or membership validation step in `AlignedBlockList.deallocate` so foreign blocks are not trusted as node headers. This aligns `deallocate` with the existing safety expectation already present in `owns`, preventing dereference of untracked aligned bases and stopping the crash path before allocator metadata is consumed.

## Residual Risk
None

## Patch
- Patch file: `058-deallocate-trusts-masked-pointer-as-node-header.patch`
- The patch updates `std/experimental/allocator/building_blocks/aligned_block_list.d` so `deallocate` confirms the candidate block maps to a tracked node before reading `node.bAlloc` and dispatching deallocation.
- This closes the reproduced path where a forged interior pointer from an unrelated mapped page was accepted and forwarded into `BitmappedBlock.deallocate`.