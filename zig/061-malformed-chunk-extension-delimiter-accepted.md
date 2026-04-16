# Malformed Chunk Extension Delimiter Accepted

## Classification

Security control failure, high severity.

## Affected Locations

- `lib/std/http/ChunkParser.zig:64`

## Summary

`std.http.ChunkParser.feed` accepted malformed HTTP chunk-size lines where the chunk size was followed by an arbitrary non-hex delimiter instead of the required `;` chunk-extension delimiter.

In `.head_size`, any byte that was not hex, `\r`, or `\n` transitioned to `.head_ext`. `.head_ext` then ignored bytes until line end and accepted the header. As a result, input such as `1 x\r\n` was parsed as a valid one-byte chunk header.

## Provenance

Verified by Swival security analysis and reproduction.

- Scanner: https://swival.dev
- Finding type: `security_control_failure`
- Severity: `high`
- Confidence: certain

## Preconditions

- Caller invokes `ChunkParser.feed` on an HTTP chunk-size line.
- The chunk-size line is attacker-controlled or otherwise untrusted.

## Proof

The vulnerable `.head_size` state treated all non-hex, non-CR, non-LF bytes as the start of a chunk extension:

```zig
else => {
    p.state = .head_ext;
    continue;
},
```

Then `.head_ext` accepted all bytes until `\n`:

```zig
.head_ext => switch (c) {
    '\r' => p.state = .head_r,
    '\n' => {
        p.state = .data;
        return i + 1;
    },
    else => continue,
},
```

Therefore this malformed chunk header was accepted:

```text
1 x\r\n
```

Runtime behavior against the affected code:

```zig
var p = std.http.ChunkParser.init;
const n = p.feed("1 x\r\n");

// n == 5
// p.state == .data
// p.chunk_len == 1
```

The same behavior was reachable through the normal HTTP chunked body path because `http.Reader.bodyReader(.chunked, ...)` calls `ChunkParser.feed`. A chunked body such as:

```text
1 x\r\n
A\r\n
0\r\n
\r\n
```

was decoded as body `A` without raising `HttpChunkInvalid`.

## Why This Is A Real Bug

HTTP chunk extensions must begin with `;` after the chunk size. A space or any other arbitrary delimiter after the chunk-size digits is not a valid chunk-extension delimiter.

The parser made an allow decision for malformed framing and entered `.data`, causing invalid chunked transfer-encoding input to be accepted. This is a fail-open parsing behavior on attacker-controlled HTTP request or response bodies.

## Fix Requirement

Only enter `.head_ext` when the delimiter after the chunk-size digits is `;`.

All other non-hex, non-CR, non-LF bytes after the chunk size must set parser state to `.invalid` and stop consuming at the invalid byte.

## Patch Rationale

The patch narrows the transition from `.head_size` to `.head_ext` to the only valid chunk-extension delimiter:

```zig
';' => {
    p.state = .head_ext;
    continue;
},
```

All other unexpected bytes now invalidate the parser:

```zig
else => {
    p.state = .invalid;
    return i;
},
```

This preserves valid behavior for:

- hex chunk-size digits
- CRLF-terminated chunk headers
- LF-terminated chunk headers already accepted by this parser
- semicolon-prefixed chunk extensions

It rejects malformed extension delimiters instead of treating them as valid extensions.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/http/ChunkParser.zig b/lib/std/http/ChunkParser.zig
index 7c628ec327..756129d8d4 100644
--- a/lib/std/http/ChunkParser.zig
+++ b/lib/std/http/ChunkParser.zig
@@ -62,10 +62,14 @@ pub fn feed(p: *ChunkParser, bytes: []const u8) usize {
                     p.state = .data;
                     return i + 1;
                 },
-                else => {
+                ';' => {
                     p.state = .head_ext;
                     continue;
                 },
+                else => {
+                    p.state = .invalid;
+                    return i;
+                },
             };
 
             const new_len = p.chunk_len *% 16 +% digit;
@@ -103,7 +107,7 @@ pub fn feed(p: *ChunkParser, bytes: []const u8) usize {
 test feed {
     const testing = std.testing;
 
-    const data = "Ff\r\nf0f000 ; ext\n0\r\nffffffffffffffffffffffffffffffffffffffff\r\n";
+    const data = "Ff\r\nf0f000;ext\n0\r\nffffffffffffffffffffffffffffffffffffffff\r\n";
 
     var p = init;
     const first = p.feed(data[0..]);
@@ -113,7 +117,7 @@ test feed {
 
     p = init;
     const second = p.feed(data[first..]);
-    try testing.expectEqual(@as(u32, 13), second);
+    try testing.expectEqual(@as(u32, 11), second);
     try testing.expectEqual(@as(u64, 0xf0f000), p.chunk_len);
     try testing.expectEqual(.data, p.state);
 
```