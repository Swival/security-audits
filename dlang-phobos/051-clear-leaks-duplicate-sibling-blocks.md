# clear leaks duplicate sibling blocks

## Classification
- Type: resource lifecycle bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/building_blocks/free_tree.d:336`

## Summary
- `FreeTree.clear` deallocates only the primary node in each tree position and recurses only through `left` and `right`.
- When equal-sized free blocks are inserted, additional entries are linked through `sibling`.
- Those sibling nodes are skipped by `clear`, then become unreachable after `root = null`, leaking retained blocks back to the parent allocator.

## Provenance
- Verified from the provided reproducer and code-path analysis.
- Scanner provenance: https://swival.dev

## Preconditions
- The tree contains at least one node with duplicate siblings.

## Proof
- Duplicate-size frees are chained via `sibling` in the tree insertion path.
- `clear` walks `left` and `right`, then deallocates only `n`; it does not traverse `n.sibling`.
- After traversal, `clear` nulls `root`, making any unvisited sibling nodes permanently unreachable.
- Reproducer result: two same-sized blocks were deallocated into `FreeTree`, then `clear()` was called; observed parent allocator counters were `alloc=2 dealloc=1`.

## Why This Is A Real Bug
- The skipped sibling nodes represent allocator-owned retained blocks, not metadata only.
- `clear()` is a real cleanup path, reachable directly, from `~this()`, and from allocation desperation-mode recovery.
- Losing references before returning all retained blocks to the parent allocator is a concrete memory leak and violates expected allocator lifecycle behavior.

## Fix Requirement
- Update `clear` so each visited node fully drains and deallocates its `sibling` chain before the tree is discarded.

## Patch Rationale
- The patch makes `clear` iterate through every node in the current node's sibling chain, deallocating each duplicate block in addition to the main node.
- This is minimal, localized to cleanup logic, and preserves existing tree traversal behavior for `left` and `right`.

## Residual Risk
- None

## Patch
- Patch file: `051-clear-leaks-duplicate-sibling-blocks.patch`
- Change: modify `std/experimental/allocator/building_blocks/free_tree.d` so `clear` walks and deallocates each node's `sibling` chain before clearing `root`.