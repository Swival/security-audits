# DWARF Line Table Lookup Underflows Before First Row

## Classification

Denial of service, low severity.

## Affected Locations

- `lib/std/debug/Coverage.zig:205`

## Summary

`Coverage.resolveAddressesDwarf` can subtract one from a zero line-table index when resolving a PC that falls inside a populated DWARF range but before the first address in the compile unit line table. This causes an integer-underflow panic during coverage/source-location resolution.

## Provenance

Verified by Swival security analysis and reproduction.

Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A victim resolves addresses using attacker-controlled DWARF ranges and line table data.
- The attacker-controlled DWARF range contains the queried PC.
- The first line-table row address is greater than the queried PC.

## Proof

The vulnerable lookup is:

```zig
const entry = slc.line_table.values()[line_table_i - 1];
```

A runtime PoC using committed standard-library code built minimal DWARF sections accepted by `Dwarf.open` and `populateRanges`:

- CU range: `[0x10, 0x30)`
- Line table first row address: `0x20`
- Resolved PC: `0x10`

For this input, `resolveAddressesDwarf(..., &.{0x10}, ...)` computes:

```zig
line_table_i = std.sort.upperBound(u64, table_addrs, pc, ...);
```

Because `pc` is before the first line-table key, `upperBound` returns `0`. The subsequent loop does not increment it, and the code evaluates `line_table_i - 1`.

Observed abort:

```text
panic: integer overflow
lib/std/debug/Coverage.zig:210:60: in resolveAddressesDwarf
        const entry = slc.line_table.values()[line_table_i - 1];
                                                           ^
```

## Why This Is A Real Bug

`resolveAddressesDwarf` validates that the PC is inside a DWARF range, but it does not validate that the source-location line table has a preceding row for that PC. DWARF/debug information can be malformed or attacker-controlled in tooling workflows that resolve coverage or source locations from untrusted binaries/debug files.

The invalid case is already representable by `SourceLocation.invalid`; instead, the function panics before reaching any invalid-location handling. This gives crafted debug info a process-termination denial of service.

## Fix Requirement

Before subtracting one from `line_table_i`, check whether it is zero. If so, mark the output source location invalid and continue to the next PC.

## Patch Rationale

The patch adds the missing lower-bound guard immediately after line-table index advancement and before `line_table_i - 1` is evaluated:

```zig
if (line_table_i == 0) {
    out.* = SourceLocation.invalid;
    continue :next_pc;
}
```

This preserves existing behavior for valid PCs that have a preceding line-table row, while safely handling PCs that fall before the first row.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/debug/Coverage.zig b/lib/std/debug/Coverage.zig
index b3e16382cc..2422f99ffa 100644
--- a/lib/std/debug/Coverage.zig
+++ b/lib/std/debug/Coverage.zig
@@ -206,6 +206,10 @@ pub fn resolveAddressesDwarf(
         const slc = &cu.src_loc_cache.?;
         const table_addrs = slc.line_table.keys();
         while (line_table_i < table_addrs.len and table_addrs[line_table_i] <= pc) line_table_i += 1;
+        if (line_table_i == 0) {
+            out.* = SourceLocation.invalid;
+            continue :next_pc;
+        }
 
         const entry = slc.line_table.values()[line_table_i - 1];
         const corrected_file_index = entry.file - @intFromBool(slc.version < 5);
```