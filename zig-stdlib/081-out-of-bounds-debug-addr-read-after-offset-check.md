# Out-of-bounds debug_addr read after offset check

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/debug/Dwarf/expression.zig:313`
- `lib/std/debug/Dwarf/expression.zig:346`
- `lib/std/debug/Dwarf.zig:1267`

## Summary
`DW_OP_constx` and `DW_OP_addrx` can drive the DWARF expression evaluator into an out-of-bounds read on `.debug_addr`. The evaluator checks only `offset >= len` before slicing `@sizeOf(usize)` bytes from `context.debug_addr`, so tail offsets pass validation but still panic when `offset + @sizeOf(usize) > len`.

## Provenance
- Verified from the supplied finding and reproducer against the committed tree
- Reproduced locally with `zig test ... --zig-lib-dir lib`
- Scanner source: https://swival.dev

## Preconditions
- Attacker-controlled DWARF expression
- A `compile_unit.addr_base` that permits a tail `.debug_addr` offset
- A short `.debug_addr` slice in evaluation context
- Evaluation through the public DWARF expression API with `DW_OP_constx` or `DW_OP_addrx`

## Proof
A minimal PoC used:
- `compile_unit.addr_base = 8`
- `.debug_addr.len = 14`
- Expression `DW_OP_constx 1`

Execution reached `lib/std/debug/Dwarf/expression.zig:346` and aborted with:
```text
panic: index out of bounds: index 17, len 14
```

The failing path is:
- Operand is parsed from expression bytes as `u64`
- `step` computes `offset = context.compile_unit.?.addr_base + debug_addr_index`
- Code checks only `offset >= context.debug_addr.?.len`
- Code then slices `context.debug_addr.?[offset..][0..@sizeOf(usize)]`

That final slice requires `offset + @sizeOf(usize) <= len`, which is not enforced.

## Why This Is A Real Bug
The crash is directly reachable from malformed DWARF input through the public evaluator API and causes a deterministic bounds panic. This is a practical denial-of-service condition for consumers that evaluate untrusted DWARF expressions with `.debug_addr` context. The in-tree `SelfUnwinder` CFA restriction does not eliminate the bug in the exposed API.

## Fix Requirement
Reject any `.debug_addr` access unless a full `@sizeOf(usize)` entry fits from the computed offset, using overflow-safe bounds logic. The check must enforce equivalent semantics to:
- `offset <= len - @sizeOf(usize)`, or
- `offset + @sizeOf(usize) <= len` with overflow protection

## Patch Rationale
The patch tightens validation at the dereference site so the evaluator fails cleanly instead of slicing past the end of `.debug_addr`. This matches the actual read width and prevents panic-triggering tail offsets. It also aligns the evaluator with the existing pattern in `lib/std/debug/Dwarf.zig:1267`, which validates the full address-width read before accessing `.debug_addr`.

## Residual Risk
None

## Patch
Patched in `081-out-of-bounds-debug-addr-read-after-offset-check.patch`.