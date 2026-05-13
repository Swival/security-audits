# deallocateAll leaves slack accounting stale

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/building_blocks/stats_collector.d:524`

## Summary
`StatsCollector.deallocateAllImpl` resets `_bytesUsed` but leaves `_bytesSlack` unchanged before forwarding to `parent.deallocateAll()`. When slack tracking is enabled, this leaves stale internal-fragmentation accounting after the allocator is fully emptied.

## Provenance
- Verified from a reproduced finding and patch generation workflow
- Source artifact: `068-deallocateall-leaves-slack-accounting-stale.patch`
- Scanner reference: https://swival.dev

## Preconditions
- `deallocateAll` exists
- `Options.bytesSlack` tracking is enabled

## Proof
Calling `StatsCollector.deallocateAll()` reaches `deallocateAllImpl` at `std/experimental/allocator/building_blocks/stats_collector.d:524`, where `numDeallocateAll` is incremented and `_bytesUsed` is set to `0`, but `_bytesSlack` is not cleared.
Allocation paths accumulate slack via `goodAllocSize - requestedSize`, and per-block `deallocate` paths subtract that slack when individual blocks are freed. `deallocateAll` bypasses per-block slack reconciliation, so after all allocations are released, `bytesUsed == 0` while `bytesSlack` retains a prior positive value.

Reproduced with `StatsCollector!(BorrowedRegion!(), Options.all)` over a byte buffer and a 42-byte allocation on an 8-byte-aligned target:
```text
len=42 align=8
used1=42 slack1=6
ok=true used2=0 slack2=6 empty=Ternary(2)
```
This demonstrates an empty parent allocator with stale slack accounting.

## Why This Is A Real Bug
`bytesSlack` is exposed as current allocator state, not historical telemetry. After `deallocateAll`, the allocator is empty, so current live slack must be zero. Leaving a nonzero value violates the collector's own accounting invariant and can mislead callers that consume these statistics for diagnostics, assertions, or allocator behavior checks.

## Fix Requirement
Reset `_bytesSlack` to `0` inside `deallocateAllImpl` when slack tracking is enabled, alongside the existing `_bytesUsed = 0` reset.

## Patch Rationale
`deallocateAll` semantically frees every live allocation in one step. Because no per-allocation `deallocate` callbacks occur, aggregate counters that represent live state must be explicitly zeroed in this path. Clearing `_bytesSlack` restores consistency with the allocator's empty state and matches the behavior implied by individual deallocation accounting.

## Residual Risk
None

## Patch
The patch in `068-deallocateall-leaves-slack-accounting-stale.patch` updates `std/experimental/allocator/building_blocks/stats_collector.d` so that `deallocateAllImpl` clears `_bytesSlack` when `Options.bytesSlack` is enabled before delegating to `parent.deallocateAll()`.