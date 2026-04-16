# Zero-Sized Mach-O Load Commands Stall Iteration

## Classification

Denial of service, medium severity.

## Affected Locations

- `lib/std/macho.zig:1089`
- Patched function: `LoadCommandIterator.next`

## Summary

`LoadCommandIterator.next()` accepted Mach-O load commands whose `cmdsize` was smaller than the fixed `load_command` header size. When `cmdsize == 0`, the iterator peeked the same header repeatedly and consumed no bytes, while still incrementing `next_index`. An attacker-controlled Mach-O with a very large `ncmds` could therefore force billions of iterations over the same 8-byte load-command buffer, causing CPU exhaustion.

## Provenance

Verified by Swival security analysis and reproduction.

Scanner: [https://swival.dev](https://swival.dev)

## Preconditions

- A victim iterates `LoadCommandIterator` over an attacker-supplied Mach-O file.
- The Mach-O header is accepted far enough for load-command iteration.
- The attacker controls `ncmds`, `sizeofcmds`, and the first load command.
- The first load command has `cmdsize = 0` or otherwise less than `@sizeOf(load_command)`.

## Proof

The vulnerable code path:

```zig
const hdr = it.r.peekStruct(load_command, .little) catch |err| switch (err) {
    error.ReadFailed => unreachable,
    error.EndOfStream => return error.InvalidMachO,
};
const data = it.r.take(hdr.cmdsize) catch |err| switch (err) {
    error.ReadFailed => unreachable,
    error.EndOfStream => return error.InvalidMachO,
};

it.next_index += 1;
return .{ .hdr = hdr, .data = data };
```

`peekStruct` reads the current `load_command` header without advancing the reader. Progress depends on `take(hdr.cmdsize)`. If `hdr.cmdsize == 0`, `take` consumes no bytes, so the reader remains positioned at the same header.

The reproduced case used an 8-byte all-zero load-command buffer and `ncmds = 5`. Every iteration returned:

- `cmd = NONE`
- `cmdsize = 0`
- `data_len = 0`
- `reader_seek = 0`

Thus the same header was returned repeatedly.

A practical malicious Mach-O can use:

- valid `MH_MAGIC_64`
- matching CPU type
- `filetype = MH_OBJECT` or `MH_DYLIB`
- `sizeofcmds = 8`
- very large `ncmds`, up to `0xffffffff`
- first load command `{ cmd = LC_NONE or another ignored command, cmdsize = 0 }`

For ignored commands, consumers may not cast or reject the command early, so iteration continues until attacker-controlled `ncmds` is exhausted.

## Why This Is A Real Bug

Mach-O load commands are length-prefixed records, and every valid command must at least contain the fixed `load_command` header. A `cmdsize` smaller than `@sizeOf(load_command)` is malformed and cannot describe a valid command.

The existing `init` check only ensured `sizeofcmds` was large enough for one `load_command` when `ncmds > 0`; it did not validate each command’s own `cmdsize`. As a result, a tiny malformed input could induce attacker-controlled CPU work. With `ncmds = 0xffffffff`, iteration can require billions of loop iterations over the same bytes before returning `null`.

This is reachable through Mach-O parsing/linking paths that accept object or dylib inputs and iterate load commands.

## Fix Requirement

Reject any load command whose `cmdsize` is smaller than `@sizeOf(load_command)` before calling `take(hdr.cmdsize)`.

## Patch Rationale

The patch adds the required structural validation immediately after peeking the load-command header and before consuming command bytes:

```zig
if (hdr.cmdsize < @sizeOf(load_command)) return error.InvalidMachO;
```

This guarantees that every successful `next()` call advances by at least the size of a load-command header. It also rejects malformed truncated logical commands before exposing them to consumers.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/macho.zig b/lib/std/macho.zig
index 9fdce9dd66..a57e787fd0 100644
--- a/lib/std/macho.zig
+++ b/lib/std/macho.zig
@@ -1966,6 +1966,7 @@ pub const LoadCommandIterator = struct {
             error.ReadFailed => unreachable,
             error.EndOfStream => return error.InvalidMachO,
         };
+        if (hdr.cmdsize < @sizeOf(load_command)) return error.InvalidMachO;
         const data = it.r.take(hdr.cmdsize) catch |err| switch (err) {
             error.ReadFailed => unreachable,
             error.EndOfStream => return error.InvalidMachO,
```