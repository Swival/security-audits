# Oversized DW_AT_addr_base Panics Before Bounds Validation

## Classification

Denial of service, medium severity.

## Affected Locations

- `lib/std/debug/Dwarf.zig:884`
- Root cause in `readDebugAddr` at `lib/std/debug/Dwarf.zig:1259`

## Summary

`std.debug.Dwarf` accepted an attacker-controlled `DW_AT_addr_base` and used it to slice `.debug_addr` before validating that the base offset was within the section. If `DW_AT_addr_base` was larger than `.debug_addr.len`, safe builds triggered a bounds-check panic instead of returning `error.InvalidDebugInfo`, aborting the DWARF-consuming process.

## Provenance

Verified by Swival security analysis and reproduction.

- Scanner: https://swival.dev
- Finding: oversized `DW_AT_addr_base` panics before bounds validation

## Preconditions

- Victim opens attacker-supplied DWARF/object/debug sections.
- Runtime safety bounds checks are enabled.
- Attacker controls a compile unit containing:
  - oversized `DW_AT_addr_base`
  - an address attribute encoded with `DW_FORM_addrx`

## Proof

The reproduced test used public `std.debug.Dwarf.open()` with attacker-controlled section bytes:

- `.debug_info`: one DWARF v5 compile unit DIE with:
  - `DW_AT_addr_base = 256`
  - `DW_AT_low_pc = DW_FORM_addrx`, index `0`
- `.debug_abbrev`: matching abbreviation table
- `.debug_addr`: empty section

Execution aborted with:

```text
panic: index out of bounds: index 254, len 0
/opt/zig/lib/std/debug/Dwarf.zig:1264:79: in readDebugAddr
    const version = mem.readInt(u16, debug_addr[compile_unit.addr_base - 4 ..][0..2], endian);
...
/opt/zig/lib/std/debug/Dwarf.zig:635:45: in scanAllCompileUnits
...
/opt/zig/lib/std/debug/Dwarf.zig:312:30: in open
```

The crash path is:

1. `scanAllFunctions` / `scanAllCompileUnits` parse `DW_AT_addr_base` into `compile_unit.addr_base`.
2. `Die.getAttrAddr` resolves `DW_FORM_addrx` via `di.readDebugAddr`.
3. `readDebugAddr` only checked `compile_unit.addr_base < 8`.
4. It then evaluated:

```zig
debug_addr[compile_unit.addr_base - 4 ..][0..2]
```

5. With `addr_base = 256` and empty `.debug_addr`, the slice panicked before invalid-DWARF handling.

## Why This Is A Real Bug

DWARF input is untrusted when reading object files, debug files, or crash/debug artifacts. The parser already models malformed DWARF as recoverable errors such as `error.InvalidDebugInfo`. This case bypassed that error path and caused a safety panic from attacker-controlled section contents.

The panic is reachable through public API use of `std.debug.Dwarf.open()` and aborts the consuming process, making it a denial-of-service vulnerability.

## Fix Requirement

Before slicing `.debug_addr` relative to `compile_unit.addr_base`, validate that:

- `compile_unit.addr_base >= 8`
- `compile_unit.addr_base <= debug_addr.len`

Invalid values must return `bad()` / `error.InvalidDebugInfo`, not panic.

## Patch Rationale

The patch extends the existing lower-bound validation with an upper-bound validation against `.debug_addr.len`.

This guarantees the subsequent header reads:

```zig
debug_addr[compile_unit.addr_base - 4 ..][0..2]
debug_addr[compile_unit.addr_base - 2]
debug_addr[compile_unit.addr_base - 1]
```

are only attempted when `addr_base` points within the section and the four-byte header suffix before `addr_base` is available. Because `addr_base >= 8`, `addr_base - 4` is non-underflowing and the two-byte version read is in bounds when `addr_base <= debug_addr.len`.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/debug/Dwarf.zig b/lib/std/debug/Dwarf.zig
index 439e590dae..87166fbe2b 100644
--- a/lib/std/debug/Dwarf.zig
+++ b/lib/std/debug/Dwarf.zig
@@ -1259,7 +1259,7 @@ fn readDebugAddr(di: Dwarf, endian: Endian, compile_unit: *const CompileUnit, in
     // need to read the header to know the size of each item. Empirically,
     // it may disagree with is_64 on the compile unit.
     // The header is 8 or 12 bytes depending on is_64.
-    if (compile_unit.addr_base < 8) return bad();
+    if (compile_unit.addr_base < 8 or compile_unit.addr_base > debug_addr.len) return bad();
 
     const version = mem.readInt(u16, debug_addr[compile_unit.addr_base - 4 ..][0..2], endian);
     if (version != 5) return bad();
```