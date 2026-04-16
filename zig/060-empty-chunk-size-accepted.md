# Empty Chunk Size Accepted

## Classification

Security control failure — HTTP chunked transfer framing validation failure.

Severity: High.

Confidence: Certain.

## Affected Locations

- `lib/std/http/ChunkParser.zig:60`
- Function: `ChunkParser.feed`

## Summary

`ChunkParser.feed` accepted an empty chunk-size line as a valid zero-length chunk.

Both `"\n"` and `"\r\n"` could transition the parser from `.head_size` to `.data` while `chunk_len` remained `0`, even though HTTP chunked framing requires `chunk-size` to contain at least one hexadecimal digit.

When used by the HTTP body reader, this allowed a chunked message beginning with an empty chunk-size boundary to be treated as complete after an empty trailer terminator.

## Provenance

Reported and reproduced by Swival security analysis.

Scanner: [https://swival.dev](https://swival.dev)

## Preconditions

- Caller uses `ChunkParser.feed` for `Transfer-Encoding: chunked` framing.
- Input is attacker-controlled or otherwise untrusted HTTP chunked body data.

## Proof

Initial parser state:

```zig
.state = .head_size
.chunk_len = 0
```

Before the patch, in `.head_size`:

```zig
'\r' => {
    p.state = .head_r;
    continue;
},
'\n' => {
    p.state = .data;
    return i + 1;
},
```

And in `.head_r`:

```zig
'\n' => {
    p.state = .data;
    return i + 1;
},
```

No hexadecimal digit was required before accepting the line ending.

Therefore both inputs were accepted:

```zig
p.feed("\n");   // state = .data, chunk_len = 0
p.feed("\r\n"); // state = .data, chunk_len = 0
```

This is reachable through the actual HTTP body reader. Chunked bodies call `ChunkParser.feed`; on `.invalid` they return `error.HttpChunkInvalid`, but on `.data` they trust `cp.chunk_len`.

If `cp.chunk_len == 0`, trailers are parsed. Thus a remote peer could send:

```text
\r\n\r\n
```

The first CRLF was accepted as an empty zero-size chunk, and the second CRLF as the empty trailer terminator, causing the body reader to mark the message complete.

## Why This Is A Real Bug

HTTP chunked framing requires the `chunk-size` field to contain at least one hexadecimal digit.

The parser violated that invariant by accepting CRLF or LF before any digit was parsed. This is a fail-open parse of message framing syntax, not merely permissive whitespace handling.

Because `chunk_len` remained `0`, downstream HTTP code interpreted the malformed boundary as the terminating zero-size chunk. No later committed-code check rejected this case.

## Fix Requirement

Track whether at least one chunk-size hexadecimal digit has been seen.

Reject:

- `\n` before any digit
- `\r\n` before any digit
- chunk extensions before any digit

Reset the tracking state when moving back to `.head_size` for the next chunk header.

## Patch Rationale

The patch adds `digit_seen: bool`.

It is set to `true` only after a valid hexadecimal chunk-size digit is parsed.

The parser now rejects CR, LF, or extension-starting bytes in `.head_size` unless `digit_seen` is already true.

The patch also resets `digit_seen` when the parser finishes a chunk data suffix and returns to `.head_size`, ensuring the invariant is enforced independently for every chunk.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/http/ChunkParser.zig b/lib/std/http/ChunkParser.zig
index 7c628ec327..34352aedb6 100644
--- a/lib/std/http/ChunkParser.zig
+++ b/lib/std/http/ChunkParser.zig
@@ -5,6 +5,7 @@ const std = @import("std");
 
 state: State,
 chunk_len: u64,
+digit_seen: bool = false,
 
 pub const init: ChunkParser = .{
     .state = .head_size,
@@ -36,14 +37,20 @@ pub fn feed(p: *ChunkParser, bytes: []const u8) usize {
     for (bytes, 0..) |c, i| switch (p.state) {
         .data_suffix => switch (c) {
             '\r' => p.state = .data_suffix_r,
-            '\n' => p.state = .head_size,
+            '\n' => {
+                p.state = .head_size;
+                p.digit_seen = false;
+            },
             else => {
                 p.state = .invalid;
                 return i;
             },
         },
         .data_suffix_r => switch (c) {
-            '\n' => p.state = .head_size,
+            '\n' => {
+                p.state = .head_size;
+                p.digit_seen = false;
+            },
             else => {
                 p.state = .invalid;
                 return i;
@@ -55,14 +62,26 @@ pub fn feed(p: *ChunkParser, bytes: []const u8) usize {
                 'A'...'Z' => |b| b - 'A' + 10,
                 'a'...'z' => |b| b - 'a' + 10,
                 '\r' => {
+                    if (!p.digit_seen) {
+                        p.state = .invalid;
+                        return i;
+                    }
                     p.state = .head_r;
                     continue;
                 },
                 '\n' => {
+                    if (!p.digit_seen) {
+                        p.state = .invalid;
+                        return i;
+                    }
                     p.state = .data;
                     return i + 1;
                 },
                 else => {
+                    if (!p.digit_seen) {
+                        p.state = .invalid;
+                        return i;
+                    }
                     p.state = .head_ext;
                     continue;
                 },
@@ -74,6 +93,7 @@ pub fn feed(p: *ChunkParser, bytes: []const u8) usize {
                 return i;
             }
 
+            p.digit_seen = true;
             p.chunk_len = new_len;
         },
         .head_ext => switch (c) {
```