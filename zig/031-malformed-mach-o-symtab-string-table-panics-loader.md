# Malformed Mach-O Symtab String Table Panics Loader

## Classification

Denial of service, low severity.

## Affected Locations

- `lib/std/debug/MachOFile.zig:109`
- `MachOFile.load`

## Summary

`MachOFile.load` trusted the `LC_SYMTAB` string table fields before slicing the mapped Mach-O file. A malformed Mach-O with `strsize == 0`, `stroff` past EOF, or `stroff + strsize` past EOF could trigger a Zig runtime panic instead of returning `error.InvalidMachO`.

## Provenance

Verified and patched from a Swival.dev Security Scanner finding.

Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A victim process calls `MachOFile.load`.
- The path supplied to `MachOFile.load` resolves to an attacker-controlled malformed Mach-O/debug file.
- The file contains enough valid structure to reach `LC_SYMTAB` processing, including:
  - valid `MH_MAGIC_64` header
  - `LC_SYMTAB`
  - `__TEXT` `LC_SEGMENT_64`

## Proof

The vulnerable code executed:

```zig
const strings = mapped_macho[symtab.stroff..][0 .. symtab.strsize - 1];
```

before validating:

- `symtab.strsize != 0`
- `symtab.stroff <= mapped_macho.len`
- `symtab.stroff + symtab.strsize <= mapped_macho.len`
- the string table ends in NUL

Confirmed malformed inputs:

- `strsize = 0` caused runtime panic at line 109: `integer overflow`
- `stroff` beyond EOF caused runtime panic at line 109: `index out of bounds`
- oversized `strsize` caused runtime panic at line 109: `index out of bounds`

These panics occurred before `MachOFile.load` could return an error.

## Why This Is A Real Bug

`MachOFile.load` is an error-returning parser for external debug information. Malformed Mach-O input should be rejected with `error.InvalidMachO`, not crash the caller process through bounds or integer-underflow panics.

The `loadOFile` path already performs analogous validation for object-file symbol string tables, showing that validating `stroff`, `strsize`, and the trailing NUL is expected parser behavior.

## Fix Requirement

Before slicing the string table in `MachOFile.load`, validate that:

- `strsize` is nonzero
- `stroff` is within the mapped Mach-O
- `stroff + strsize` fits within the mapped Mach-O without overflow
- the final byte of the string table is NUL

Invalid values must return `error.InvalidMachO`.

## Patch Rationale

The patch adds explicit validation immediately before the existing string-table slice:

```zig
if (symtab.strsize == 0) return error.InvalidMachO;
if (symtab.stroff > mapped_macho.len or symtab.strsize > mapped_macho.len - symtab.stroff) return error.InvalidMachO;
if (mapped_macho[symtab.stroff + symtab.strsize - 1] != 0) return error.InvalidMachO;
```

This prevents:

- underflow in `symtab.strsize - 1`
- out-of-bounds slicing at `mapped_macho[symtab.stroff..]`
- out-of-bounds slicing of the string table length
- accepting unterminated string tables

The bounds expression uses subtraction after checking `stroff > mapped_macho.len`, avoiding overflow in `stroff + strsize`.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/debug/MachOFile.zig b/lib/std/debug/MachOFile.zig
index 4b2fb524bc..8016a3cf12 100644
--- a/lib/std/debug/MachOFile.zig
+++ b/lib/std/debug/MachOFile.zig
@@ -106,6 +106,9 @@ pub fn load(gpa: Allocator, io: Io, path: []const u8, arch: std.Target.Cpu.Arch)
         };
     };
 
+    if (symtab.strsize == 0) return error.InvalidMachO;
+    if (symtab.stroff > mapped_macho.len or symtab.strsize > mapped_macho.len - symtab.stroff) return error.InvalidMachO;
+    if (mapped_macho[symtab.stroff + symtab.strsize - 1] != 0) return error.InvalidMachO;
     const strings = mapped_macho[symtab.stroff..][0 .. symtab.strsize - 1];
 
     var symbols: std.ArrayList(Symbol) = try .initCapacity(gpa, symtab.nsyms);
```