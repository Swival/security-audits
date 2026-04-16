# SIMD Path Misses LF-Only Header Terminators

## Classification

Request smuggling / HTTP framing desynchronization. Severity: medium. Confidence: certain.

## Affected Locations

- `lib/std/http/HeadParser.zig:127`

## Summary

`std.http.HeadParser.feed` has a SIMD fast path for scanning HTTP header terminators. When a SIMD-sized chunk contains exactly two CR/LF bytes, the parser only checks the last two bytes of the chunk for `"\n\n"`. If the only LF-only terminator occurs earlier in the chunk, the parser misses it, advances by the full SIMD chunk length, and consumes bytes after the header boundary as header bytes.

For LF-tolerant callers, this can desynchronize HTTP framing by moving body or next-message bytes into the parsed head.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

The finding was reproduced against the committed source and patched in `052-simd-path-misses-lf-only-header-terminators.patch`.

## Preconditions

- A caller uses `HeadParser` on peer-controlled HTTP bytes.
- The caller accepts LF-only header terminators.
- The LF-only terminator `"\n\n"` appears inside a SIMD-sized chunk.
- That chunk contains exactly two CR/LF bytes total, and the `"\n\n"` pair is not located at the final two bytes of the chunk.

## Proof

In `.start`, when at least `vector_len` bytes remain, `feed` loads a SIMD chunk and counts bytes equal to `'\r'` or `'\n'`.

For `matches == 2`, the vulnerable code only inspects:

```zig
const b16 = int16(chunk[vector_len - 2 ..][0..2]);
```

It then checks whether those final two bytes equal `"\n\n"`.

A peer can place the only `"\n\n"` earlier in the SIMD chunk, followed by body bytes. Because the SIMD chunk contains exactly two CR/LF bytes total, `matches == 2` is selected, but the real terminator is not checked. The parser then executes:

```zig
index += vector_len;
continue;
```

Those post-terminator bytes are treated as header bytes.

The reproducer confirmed this at runtime against the committed source. On the target, `vector_len == 16`; with `"\n\n"` at offsets `4,5` and a later `"\r\n\r\n"`, the correct LF-only header length is `6`, but `HeadParser.feed` returned `24` with state `finished`, consuming 18 bytes past the LF-only boundary.

This is reachable through `std.http.Reader.receiveHead`, which directly accumulates bytes consumed by `HeadParser.feed` and removes them from the input buffer:

```zig
head_len += hp.feed(remaining);
...
const head_buffer = in.buffered()[0..head_len];
in.toss(head_len);
```

## Why This Is A Real Bug

`HeadParser` explicitly recognizes LF-only header termination in multiple scalar paths, including `"\n\n"`. Therefore, the SIMD path must preserve the same semantics.

The SIMD path does not. For exactly two CR/LF bytes, it assumes any relevant two-byte terminator must be at the end of the SIMD chunk. That assumption is false. A valid LF-only terminator can appear earlier, followed by body or pipelined-message bytes containing no CR/LF. The parser then consumes beyond the true boundary.

This creates concrete HTTP framing desynchronization for LF-tolerant users of `HeadParser` or `Reader.receiveHead`: bytes that should remain as body or next-message data are included in the returned head buffer and tossed from the stream.

## Fix Requirement

When a SIMD chunk contains exactly two CR/LF bytes, the implementation must scan for the actual `"\n\n"` position rather than checking only `chunk[vector_len - 2..][0..2]`.

Acceptable fixes include:

- scanning all possible `"\n\n"` offsets in the SIMD chunk, or
- deriving and checking the actual CR/LF positions.

The parser must return immediately at the real LF-only terminator offset.

## Patch Rationale

The patch adds an early scan for `"\n\n"` when `matches == 2`:

```zig
if (matches == 2) {
    inline for (0..vector_len - 1) |i_usize| {
        const i = @as(u32, @truncate(i_usize));

        if (int16(chunk[i..][0..2]) == int16("\n\n")) {
            p.state = .finished;
            return index + i + 2;
        }
    }
}
```

This preserves the existing SIMD structure while correcting the missed case. If `"\n\n"` appears anywhere in the SIMD chunk, the parser now finishes and returns the precise header length. If no `"\n\n"` exists, execution falls through to the existing `matches == 2` handling, preserving prior state-transition behavior for trailing CR/LF sequences.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/http/HeadParser.zig b/lib/std/http/HeadParser.zig
index 7b9ca6d2c5..4fc308b2a8 100644
--- a/lib/std/http/HeadParser.zig
+++ b/lib/std/http/HeadParser.zig
@@ -124,6 +124,17 @@ pub fn feed(p: *HeadParser, bytes: []const u8) usize {
                     const matches_or: SizeVector = matches_r | matches_n;
 
                     const matches = @reduce(.Add, matches_or);
+                    if (matches == 2) {
+                        inline for (0..vector_len - 1) |i_usize| {
+                            const i = @as(u32, @truncate(i_usize));
+
+                            if (int16(chunk[i..][0..2]) == int16("\n\n")) {
+                                p.state = .finished;
+                                return index + i + 2;
+                            }
+                        }
+                    }
+
                     switch (matches) {
                         0 => {},
                         1 => switch (chunk[vector_len - 1]) {
```