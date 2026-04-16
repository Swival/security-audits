# Unchecked debug_addr offset arithmetic wraps before validation

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/debug/Dwarf.zig:877`
- `lib/std/debug/Dwarf.zig:759`
- `lib/std/debug/Dwarf.zig:778`

## Summary
`readDebugAddr` computes `byte_offset = compile_unit.addr_base + (addr_size + seg_size) * index` before validating that the resulting slice fits within `.debug_addr`. In `ReleaseFast`, the unchecked multiply/add can wrap for attacker-controlled `addrx` and `RLE.*x` indices, causing the subsequent bounds check to succeed on a wrapped offset and returning the wrong `.debug_addr` entry instead of rejecting malformed DWARF.

## Provenance
- Verified from the supplied reproducer and patch context
- Swival Security Scanner: https://swival.dev

## Preconditions
- Attacker-controlled DWARF with oversized `addrx` or rnglist index
- Build mode where integer overflow wraps rather than trapping, such as `ReleaseFast`

## Proof
The vulnerable logic accepts attacker-influenced indices from DWARF forms and range list entries, then performs unchecked offset arithmetic in `readDebugAddr`.

A minimal reproduction using the committed logic demonstrates the failure mode in `ReleaseFast`:
- `addr_base = 8`
- `addr_size = 8`
- `seg_size = 0`
- `index = 1 << 61`

Under wrapping arithmetic:
- `(addr_size + seg_size) * index` becomes `8 * (1 << 61)` and wraps to `0`
- `byte_offset` becomes `8 + 0 = 8`
- The bounds check against a minimal `.debug_addr` buffer passes
- The function returns the first address entry, `0x1122334455667788`, for a massively out-of-range index

In safety-enabled builds, Zig traps on the overflowing arithmetic before the bounds check. That does not eliminate the bug; it shows the behavior is build-dependent.

## Why This Is A Real Bug
This is a correctness and validation failure on untrusted debug data. The function is intended to reject out-of-range indexed address lookups, but in optimized wrapping builds it can silently reinterpret a huge invalid index as a valid in-bounds offset. That corrupts DWARF-driven address resolution and range decoding in downstream callers, including compile unit and range population paths reachable through `DebugRangeIterator`, yielding incorrect symbol, source, or range results from malformed input.

## Fix Requirement
Use checked arithmetic for both the stride multiplication and `addr_base` addition before any bounds comparison against `.debug_addr.len`. Reject the lookup if either operation overflows.

## Patch Rationale
The patch hardens `readDebugAddr` by replacing unchecked offset arithmetic with checked `mul`/`add` style computation before slicing `.debug_addr`. This preserves existing semantics for valid DWARF while ensuring oversized indices fail closed instead of wrapping into a smaller offset.

## Residual Risk
None

## Patch
- Patch file: `073-unchecked-debug-addr-index-multiplication-can-bypass-bounds-.patch`
- The patch adds checked offset computation in `lib/std/debug/Dwarf.zig` so malformed `addrx` and `RLE.*x` indices are rejected before `.debug_addr` is accessed.