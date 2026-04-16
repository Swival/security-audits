# Malformed Mach-O Symbol String Index Panics Loader

## Classification

Denial of service, low severity.

## Affected Locations

- `lib/std/debug/MachOFile.zig:145`

## Summary

`std.debug.MachOFile.load` used the file-controlled Mach-O symbol string-table index `sym.n_strx` as a slice start without first validating that it was within the parsed string table. A malformed Mach-O debug file with `n_strx > strings.len` caused a Zig bounds-check panic in safety-enabled builds instead of returning `error.InvalidMachO`.

## Provenance

Verified and patched from a Swival security finding.

Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The application loads attacker-controlled Mach-O debug info.
- Runtime safety is enabled.

## Proof

`MachOFile.load` parses the Mach-O string table as:

```zig
const strings = mapped_macho[symtab.stroff..][0 .. symtab.strsize - 1];
```

When iterating symbols, a non-STAB `N_SECT` symbol with nonzero `n_strx` reached:

```zig
const name = std.mem.sliceTo(strings[sym.n_strx..], 0);
```

without checking `sym.n_strx <= strings.len`.

A minimal 64-bit Mach-O file reproduced the issue with:

- valid `MH_MAGIC_64`
- `LC_SEGMENT_64` named `__TEXT`
- `LC_SYMTAB`
- `strsize = 2`, making `strings.len == 1`
- one non-STAB `N_SECT` symbol with `n_strx = 2`

Running `std.debug.MachOFile.load` in Debug mode panicked:

```text
panic: start index 2 is larger than end index 1
lib/std/debug/MachOFile.zig:145:57: in load
    const name = std.mem.sliceTo(strings[sym.n_strx..], 0);
```

## Why This Is A Real Bug

Mach-O debug input is parsed from a caller-supplied path and may be malformed or attacker-controlled. Invalid symbol metadata should be rejected as `error.InvalidMachO`. Instead, the unchecked `n_strx` value can trigger a runtime bounds panic, terminating the process in safety-enabled builds.

## Fix Requirement

Validate every parsed symbol `n_strx` before any use as an index into `strings`. If `n_strx > strings.len`, return `error.InvalidMachO`.

## Patch Rationale

The patch adds a bounds check immediately after each symbol is decoded and before any STAB or non-STAB handling can slice `strings` using `sym.n_strx`. This rejects malformed indexes consistently and prevents the panic.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/debug/MachOFile.zig b/lib/std/debug/MachOFile.zig
index 4b2fb524bc..77b2082ee3 100644
--- a/lib/std/debug/MachOFile.zig
+++ b/lib/std/debug/MachOFile.zig
@@ -137,6 +137,7 @@ pub fn load(gpa: Allocator, io: Io, path: []const u8, arch: std.Target.Cpu.Arch)
             error.ReadFailed => unreachable,
             error.EndOfStream => return error.InvalidMachO,
         };
+        if (sym.n_strx > strings.len) return error.InvalidMachO;
         if (sym.n_type.bits.is_stab == 0) {
             if (sym.n_strx == 0) continue;
             switch (sym.n_type.bits.type) {
```