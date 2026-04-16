# Malformed ELF Dynamic Section Offset Panics Buffer Iterator

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

- `lib/std/elf.zig:852`
- `DynamicSectionBufferIterator.next`

## Summary

`Header.iterateDynamicSectionBuffer` accepts caller-provided ELF dynamic section `offset` and `size` and stores them as iterator bounds without validating them against the supplied in-memory buffer length. `DynamicSectionBufferIterator.next` only checks whether `offset >= end_offset`; if `offset` is past `buf.len` but still below `end_offset`, it slices `it.buf[it.offset..]`, causing a Zig bounds panic instead of returning an error.

## Provenance

Verified by Swival security analysis. Scanner: https://swival.dev

## Preconditions

- Victim parses an untrusted ELF dynamic section from an in-memory buffer.
- The parser follows the public buffer-based ELF parsing flow:
  1. `Header.read`
  2. `iterateProgramHeadersBuffer`
  3. find `PT_DYNAMIC`
  4. call `iterateDynamicSectionBuffer(buf, phdr.p_offset, phdr.p_filesz)`
  5. call `next()`

## Proof

A crafted ELF can set the dynamic segment file offset past the supplied buffer while keeping `offset < offset + size`.

Observed reproduced case:

- Buffer length: `128`
- Dynamic section offset: `200`
- Dynamic section size: `16`
- Iterator state:
  - `offset = 200`
  - `end_offset = 216`

`next()` does not stop because `200 < 216`, then evaluates:

```zig
var reader: std.Io.Reader = .fixed(it.buf[it.offset..]);
```

This attempts `buf[200..]` on a 128-byte buffer and aborts in a safety-checked Zig build with:

```text
panic: start index 200 is larger than end index 128
```

The panic occurs before `takeDynamicSection` can return `error.EndOfStream`.

## Why This Is A Real Bug

The API is a public in-memory ELF parser path intended to return parse errors for malformed input. A malformed ELF offset should be handled as invalid or truncated input, not as a process-aborting bounds panic. Under the stated precondition, attacker-controlled ELF data can terminate the parser process, producing denial of service.

## Fix Requirement

Before slicing the buffer, validate that the current dynamic section offset is within `buf.len`. If the offset is past the supplied buffer, return `error.EndOfStream` or an invalid ELF error instead of constructing an out-of-bounds slice.

## Patch Rationale

The patch adds a bounds check immediately after the iterator end check and before slicing:

```zig
if (it.offset > it.buf.len) return error.EndOfStream;
```

This preserves existing iterator semantics:

- `offset >= end_offset` still terminates iteration normally.
- `offset > buf.len` now reports truncated input.
- `offset == buf.len` remains valid to slice as an empty buffer, allowing `takeDynamicSection` to report `EndOfStream` if a record is required.

The slice index is then explicitly cast after the bounds check:

```zig
it.buf[@intCast(it.offset)..]
```

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/elf.zig b/lib/std/elf.zig
index 81de3f7f50..e87cea9b72 100644
--- a/lib/std/elf.zig
+++ b/lib/std/elf.zig
@@ -991,9 +991,10 @@ pub const DynamicSectionBufferIterator = struct {
 
     pub fn next(it: *DynamicSectionBufferIterator) !?Elf64_Dyn {
         if (it.offset >= it.end_offset) return null;
+        if (it.offset > it.buf.len) return error.EndOfStream;
         const size: u64 = if (it.is_64) @sizeOf(Elf64_Dyn) else @sizeOf(Elf32_Dyn);
         defer it.offset += size;
-        var reader: std.Io.Reader = .fixed(it.buf[it.offset..]);
+        var reader: std.Io.Reader = .fixed(it.buf[@intCast(it.offset)..]);
         return try takeDynamicSection(&reader, it.is_64, it.endian);
     }
 };
```