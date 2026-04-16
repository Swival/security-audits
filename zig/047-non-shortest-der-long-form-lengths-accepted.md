# Non-Shortest DER Long-Form Lengths Accepted

## Classification

- Type: `security_control_failure`
- Severity: High
- Confidence: Certain

## Affected Locations

- `lib/std/crypto/codecs/asn1.zig:215`
- Function: `Element.decode`

## Summary

`Element.decode` documents DER shortest-form length enforcement, but accepts long-form DER lengths with leading zero bytes. This permits non-canonical DER encodings such as length `128` encoded as `82 00 80`, even though DER requires the shortest valid long form `81 80`.

## Provenance

Verified by Swival security analysis and reproduction.

- Scanner: https://swival.dev

## Preconditions

- A caller uses `Element.decode` to enforce DER canonical length encoding.
- Attacker can provide ASN.1/DER bytes to that parser.

## Proof

Reproducer input:

```zig
const bad = [_]u8{ 0x04, 0x82, 0x00, 0x80 } ++ @as([128]u8, @splat(0));
const ele = asn1.Element.decode(&bad, 0) catch |err| {
    std.debug.print("rejected: {s}\n", .{@errorName(err)});
    return;
};
std.debug.print("accepted tag={d} start={d} end={d} total={d}\n",
    .{ @intFromEnum(ele.tag.number), ele.slice.start, ele.slice.end, bad.len });
```

Observed result:

```text
accepted tag=4 start=4 end=132 total=132
```

The accepted length encoding is:

```text
82 00 80
```

This is not shortest-form DER. DER length `128` must be encoded as:

```text
81 80
```

## Why This Is A Real Bug

`Element.decode` explicitly states that it ensures length uses shortest form. The implementation rejects long-form lengths whose decoded value is below `128`, but it does not reject long-form lengths with leading zero bytes.

For input:

```text
04 82 00 80 ...
```

the parser:

1. Reads tag `0x04`.
2. Reads length descriptor `0x82`, so `len_size == 2`.
3. Parses `00 80` as integer `128`.
4. Checks `len < 128`, which is false.
5. Accepts the element when the payload is present.

This deterministically fails open for a DER canonicality control.

## Fix Requirement

Reject long-form length encodings whose first length byte is zero.

## Patch Rationale

In DER long-form length encoding, the length must be encoded in the minimum number of octets. A leading zero byte proves the encoding is non-minimal. Checking the first length byte before consuming the variable integer rejects this class of non-canonical encodings while preserving valid long-form lengths.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/crypto/codecs/asn1.zig b/lib/std/crypto/codecs/asn1.zig
index faa2ffb621..a5a02d36d1 100644
--- a/lib/std/crypto/codecs/asn1.zig
+++ b/lib/std/crypto/codecs/asn1.zig
@@ -208,6 +208,10 @@ pub const Element = struct {
             // long form between 0 and std.math.maxInt(u1024)
             const len_size: u7 = @truncate(size_or_len_size);
             if (len_size > @sizeOf(Index)) return error.EndOfStream;
+            if ((reader.peekByte() catch |err| switch (err) {
+                error.ReadFailed => unreachable, // it's all fixed buffers
+                else => |e| return e,
+            }) == 0) return error.EndOfStream;
 
             const len = reader.takeVarInt(Index, .big, len_size) catch |err| switch (err) {
                 error.ReadFailed => unreachable, // it's all fixed buffers
```