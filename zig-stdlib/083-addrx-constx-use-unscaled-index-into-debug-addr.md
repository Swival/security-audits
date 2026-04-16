# addrx/constx use unscaled index into .debug_addr

## Classification
- Type: data integrity bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/debug/Dwarf/expression.zig:311`
- `lib/std/debug/Dwarf/expression.zig:345`
- `lib/std/debug/Dwarf/expression.zig:1098`
- `lib/std/debug/Dwarf/expression.zig:1113`

## Summary
`DW_OP_addrx` and `DW_OP_constx` operands are decoded as logical `.debug_addr` indices, but `StackMachine.step` adds the raw ULEB128 operand directly to `compile_unit.addr_base` and reads from `context.debug_addr` at that byte offset. This treats the index as a byte offset instead of scaling by address-entry width, so any nonzero logical index resolves to the wrong entry. Existing tests masked the bug by encoding byte offsets rather than indices.

## Provenance
- Verified from the provided reproducer and affected source in `lib/std/debug/Dwarf/expression.zig`
- Scanner source: https://swival.dev

## Preconditions
- A DWARF expression is evaluated through `StackMachine.run`
- `Context.compile_unit` and `Context.debug_addr` are populated
- The expression contains `DW_OP_addrx` or `DW_OP_constx`

## Proof
In `lib/std/debug/Dwarf/expression.zig:311`, the operand for `DW_OP_addrx` / `DW_OP_constx` is obtained from `readOperand(...)` as `operand.?.generic`, a ULEB128 logical index.

In `lib/std/debug/Dwarf/expression.zig:345`, the implementation computes:
```zig
offset = context.compile_unit.?.addr_base + debug_addr_index
```
and then reads a `usize` from `context.debug_addr.?[offset..]`.

That is incorrect for `.debug_addr`, whose entries are fixed-width address slots. The logical index must be multiplied by entry size before adding `addr_base`. As reproduced, test coverage in `lib/std/debug/Dwarf/expression.zig:1098` and `lib/std/debug/Dwarf/expression.zig:1113` used values like `1 + @sizeOf(usize)`, which are raw byte offsets, so the tests only passed because they encoded the implementation bug.

A secondary issue exists at `lib/std/debug/Dwarf/expression.zig:345`: the bounds check only validates `offset >= len`, not whether `offset + @sizeOf(usize) <= len`, allowing malformed offsets to reach an out-of-bounds slice in safe builds.

## Why This Is A Real Bug
DWARF `addrx`/`constx` operands are specified as indices into `.debug_addr`, not byte offsets. Using the unscaled operand corrupts expression evaluation for valid inputs whenever the index is nonzero and entry size exceeds 1 byte. This directly miscomputes addresses/constants and can misresolve variable locations or values during DWARF evaluation. The existing passing tests do not disprove the bug because they were written against the incorrect byte-offset behavior.

## Fix Requirement
- Scale `DW_OP_addrx` / `DW_OP_constx` indices by address-entry size before adding `addr_base`
- Strengthen bounds checking to require the full entry to fit in `context.debug_addr`
- Update tests/builders to encode logical indices, not raw byte offsets

## Patch Rationale
The patch aligns evaluation with DWARF semantics by converting the decoded ULEB128 operand from logical index to byte offset using address-entry width, then validating the entire read window before loading the entry. Test inputs are updated to use true indices so coverage now exercises compliant behavior rather than the prior bug.

## Residual Risk
None

## Patch
- Patched in `083-addrx-constx-use-unscaled-index-into-debug-addr.patch`
- The patch scales `.debug_addr` indices before lookup in `lib/std/debug/Dwarf/expression.zig`
- The patch tightens the `.debug_addr` bounds check in `lib/std/debug/Dwarf/expression.zig`
- The patch updates affected tests in `lib/std/debug/Dwarf/expression.zig:1098` and `lib/std/debug/Dwarf/expression.zig:1113` to use logical indices