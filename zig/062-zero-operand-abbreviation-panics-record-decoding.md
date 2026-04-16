# Zero-Operand Abbreviation Panics Record Decoding

## Classification

Denial of service, medium severity.

## Affected Locations

- `lib/std/zig/llvm/BitcodeReader.zig:267`
- Root cause: `lib/std/zig/llvm/BitcodeReader.zig`, `Record.toOwnedAbbrev`

## Summary

A malformed LLVM bitcode stream can define an abbreviation with zero operands and then use it. The reader accepts and stores the empty abbreviation. When the abbreviation is later decoded, `nextRecord` produces an empty operand list and unconditionally reads `operands.items[0]` for the record id, causing a runtime bounds-check panic.

## Provenance

Verified by Swival security analysis and reproduction.

Scanner: [https://swival.dev](https://swival.dev)

Confidence: certain.

## Preconditions

- A consumer parses attacker-controlled or otherwise untrusted bitcode.
- Runtime safety checks are enabled.

## Proof

`next()` accepts `DEFINE_ABBREV` records and stores `record.toOwnedAbbrev(...)`.

Before the patch, `toOwnedAbbrev` allowed `record.operands.len == 0`, returning:

```zig
.{ .operands = try operands.toOwnedSlice() }
```

where `operands.items.len == 0`.

When the attacker later selects that abbreviation, `nextRecord` allocates an operands list with capacity `0`, skips the decode loop, and then evaluates:

```zig
.id = std.math.cast(u32, operands.items[0]) orelse return error.InvalidRecordId,
```

With runtime safety enabled, this indexes an empty slice.

Confirmed with minimal bitstream:

```text
44 49 41 47  21 0c 00 00  01 00 00 00  02 04 00 00
```

Decoded as:

1. magic `"DIAG"`;
2. enter subblock id `8` with abbrev width `3`;
3. block length `1` word;
4. `DEFINE_ABBREV` with zero operands;
5. use abbreviation id `4`.

Observed result:

```text
panic: index out of bounds: index 0, len 0
lib/std/zig/llvm/BitcodeReader.zig:265:48 in nextRecord
```

## Why This Is A Real Bug

The reader treats the first decoded operand as the record id. Therefore, every usable record abbreviation must produce at least one operand. Accepting an abbreviation with no operands violates this invariant and allows malformed input to terminate the parser through a safety panic rather than returning a parse error.

Because the trigger is entirely controlled by bitcode contents, this is a reachable denial of service for consumers parsing untrusted bitcode.

## Fix Requirement

Reject abbreviations that decode to zero operands before storing or using them.

## Patch Rationale

The patch adds validation in `Record.toOwnedAbbrev`:

```zig
if (operands.items.len == 0) return error.InvalidAbbrev;
```

This rejects malformed zero-operand abbreviations at definition time, before they can be inserted into the abbreviation store and later selected by `nextRecord`.

The fix preserves the existing `nextRecord` invariant that `operands.items[0]` exists and represents the record id.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/zig/llvm/BitcodeReader.zig b/lib/std/zig/llvm/BitcodeReader.zig
index 3ed1e0e928..dd0ec350d2 100644
--- a/lib/std/zig/llvm/BitcodeReader.zig
+++ b/lib/std/zig/llvm/BitcodeReader.zig
@@ -93,6 +93,7 @@ pub const Record = struct {
             else => unreachable,
         };
 
+        if (operands.items.len == 0) return error.InvalidAbbrev;
         return .{ .operands = try operands.toOwnedSlice() };
     }
 };
```