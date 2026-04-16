# Non-Hex Letters Accepted in Chunk Sizes

## Classification

Security control failure, high severity.

## Affected Locations

- `lib/std/http/ChunkParser.zig:54`

## Summary

`ChunkParser.feed()` accepted alphabetic bytes outside hexadecimal range while parsing HTTP chunk sizes. In `.head_size`, the parser treated `G-Z` and `g-z` as valid digits and computed values greater than `15`, allowing malformed chunked transfer framing such as `G\r\n` to be accepted as a valid chunk header.

## Provenance

Verified by Swival security analysis and reproduction.

Scanner provenance: [Swival.dev Security Scanner](https://swival.dev)

Confidence: certain.

## Preconditions

- A caller uses `ChunkParser.feed()` to parse `Transfer-Encoding: chunked` chunk sizes.
- A remote or local peer can provide the chunked body bytes.

## Proof

The affected code parsed chunk-size digits with:

```zig
'A'...'Z' => |b| b - 'A' + 10,
'a'...'z' => |b| b - 'a' + 10,
```

For input:

```text
G\r\n
```

the parser behavior was:

1. Initial state is `.head_size`.
2. Byte `G` matches `'A'...'Z'`.
3. Computed digit is `16`.
4. `chunk_len` becomes `0 * 16 + 16 = 16`.
5. Byte `\r` transitions to `.head_r`.
6. Byte `\n` transitions to `.data` and returns success.

The reproduced test result was:

```text
n=3 state=data len=16
```

Thus `G\r\n` was accepted as a valid chunk header with length `16` instead of entering `.invalid`.

## Why This Is A Real Bug

HTTP chunk sizes are hexadecimal. Valid letters are only `A-F` and `a-f`. Accepting `G-Z` or `g-z` means the chunked framing parser fails open on malformed message framing.

This code is reachable through standard HTTP chunked body handling that uses `ChunkParser.feed()`. When the parser reaches `.data`, callers consume or stream `chunk_len` bytes. When the parser reaches `.invalid`, callers can reject the input, for example with `error.HttpChunkInvalid`.

Because malformed chunk-size bytes are accepted as framing, a remote HTTP peer controlling a chunked body can cause invalid transfer-encoding syntax to be parsed as valid framing.

## Fix Requirement

Restrict accepted alphabetic chunk-size digits to hexadecimal letters only:

- `A-F`
- `a-f`

All other non-delimiter bytes in the chunk-size position must not be interpreted as hex digits.

## Patch Rationale

The patch narrows the accepted uppercase and lowercase ranges from the full alphabet to the valid hexadecimal subsets. This preserves existing behavior for valid chunk sizes and prevents values greater than `15` from being computed as a single hex digit.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/http/ChunkParser.zig b/lib/std/http/ChunkParser.zig
index 7c628ec327..292d3c5355 100644
--- a/lib/std/http/ChunkParser.zig
+++ b/lib/std/http/ChunkParser.zig
@@ -52,8 +52,8 @@ pub fn feed(p: *ChunkParser, bytes: []const u8) usize {
         .head_size => {
             const digit = switch (c) {
                 '0'...'9' => |b| b - '0',
-                'A'...'Z' => |b| b - 'A' + 10,
-                'a'...'z' => |b| b - 'a' + 10,
+                'A'...'F' => |b| b - 'A' + 10,
+                'a'...'f' => |b| b - 'a' + 10,
                 '\r' => {
                     p.state = .head_r;
                     continue;
```