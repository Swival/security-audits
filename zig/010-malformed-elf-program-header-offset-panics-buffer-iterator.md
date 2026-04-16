# Malformed ELF Program Header Offset Panics Buffer Iterator

## Classification

- Type: Denial of Service
- Severity: Medium
- Confidence: Certain

## Affected Locations

- `lib/std/elf.zig:769`
- `ProgramHeaderBufferIterator.next`

## Summary

`std.elf.Header.iterateProgramHeadersBuffer` trusts the ELF `e_phoff` value copied into `Header.phoff`. If an attacker supplies an ELF buffer with `e_phoff` beyond the provided buffer and `e_phnum > 0`, `ProgramHeaderBufferIterator.next` slices `it.buf[offset..]` before validating `offset`. Zig's bounds check then panics and aborts the process instead of returning an error.

## Provenance

- Verified by Swival security analysis.
- Scanner: [Swival.dev Security Scanner](https://swival.dev)

## Preconditions

- Victim parses attacker-controlled ELF bytes.
- Victim uses `Header.read` followed by `iterateProgramHeadersBuffer`.
- Parsed ELF has `phnum > 0`.
- Parsed ELF has `phoff` greater than the supplied buffer length, or a program header entry would extend past the buffer.

## Proof

`Header.init` copies `hdr.e_phoff` directly into `Header.phoff`:

```zig
.phoff = hdr.e_phoff,
```

`iterateProgramHeadersBuffer` then stores this value in the buffer iterator:

```zig
.phoff = h.phoff,
.buf = buf,
```

Before the patch, `ProgramHeaderBufferIterator.next` computed an attacker-controlled offset and sliced without checking bounds:

```zig
const size: usize = if (it.is_64) @sizeOf(Elf64_Phdr) else @sizeOf(Elf32_Phdr);
const offset = @as(usize, @intCast(it.phoff)) + size * it.index;
var reader = Io.Reader.fixed(it.buf[offset..]);
```

A reproduced ELF64 test buffer of 64 bytes with:

- valid ELF header
- `e_phnum = 1`
- `e_phoff = 1000`

caused `Header.read` to succeed, then `header.iterateProgramHeadersBuffer(&buf).next()` aborted with:

```text
thread ... panic: start index 1000 is larger than end index 64
lib/std/elf.zig:878:44: in next
        var reader = Io.Reader.fixed(it.buf[offset..]);
```

The analogous section-header buffer iterator already guards `offset > it.buf.len` before slicing, confirming the missing program-header guard is inconsistent with nearby code.

## Why This Is A Real Bug

This is a public std.elf API used to parse buffers. Malformed input should be reported through the iterator's error return, not by triggering a process-aborting bounds panic. An attacker supplying a crafted ELF object can terminate any parser, package-processing tool, or similar consumer that calls `iterateProgramHeadersBuffer` on untrusted bytes.

The directly proven impact is denial of service against std.elf parser consumers. No in-tree Zig compiler caller of `iterateProgramHeadersBuffer` was identified in the reproduction.

## Fix Requirement

Validate the computed program header offset and the required program header size before slicing the backing buffer. Arithmetic overflow and out-of-buffer ranges must return `error.EndOfStream` rather than panic.

## Patch Rationale

The patch makes `ProgramHeaderBufferIterator.next` behave like a fallible parser:

- computes offsets in `u64`
- uses checked addition for `phoff + size * index`
- rejects offsets beyond `buf.len`
- rejects entries whose full header size is not available
- performs the slice only after all range checks pass

This converts attacker-controlled malformed ELF layout into `error.EndOfStream` instead of a runtime bounds panic.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/elf.zig b/lib/std/elf.zig
index 81de3f7f50..721b00aa9e 100644
--- a/lib/std/elf.zig
+++ b/lib/std/elf.zig
@@ -873,9 +873,12 @@ pub const ProgramHeaderBufferIterator = struct {
         if (it.index >= it.phnum) return null;
         defer it.index += 1;
 
-        const size: usize = if (it.is_64) @sizeOf(Elf64_Phdr) else @sizeOf(Elf32_Phdr);
-        const offset = @as(usize, @intCast(it.phoff)) + size * it.index;
-        var reader = Io.Reader.fixed(it.buf[offset..]);
+        const size: u64 = if (it.is_64) @sizeOf(Elf64_Phdr) else @sizeOf(Elf32_Phdr);
+        const offset = math.add(u64, it.phoff, size * it.index) catch return error.EndOfStream;
+        if (offset > it.buf.len) return error.EndOfStream;
+        const start: usize = @intCast(offset);
+        if (size > it.buf.len - start) return error.EndOfStream;
+        var reader = Io.Reader.fixed(it.buf[start..]);
 
         return try takeProgramHeader(&reader, it.is_64, it.endian);
     }
```