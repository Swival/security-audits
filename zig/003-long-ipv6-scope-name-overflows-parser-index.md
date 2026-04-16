# Long IPv6 Scope Name Overflows Parser Index

## Classification

- Type: Denial of Service
- Severity: Medium
- Confidence: Certain

## Affected Locations

- `lib/std/Io/net.zig:530`
- `lib/std/Io/net.zig:577`

## Summary

`Ip6Address.Unresolved.parse` stored parser indexes in `u8` variables. When parsing a scoped IPv6 literal containing `%`, the parser assigned `text.len` into `text_i` using `@intCast`. For scoped IPv6 inputs whose total length exceeded 255 bytes, this cast could not fit in `u8` and triggered a Zig safety trap, aborting the process instead of returning a parse error.

## Provenance

- Verified by Swival security analysis.
- Scanner: [Swival.dev Security Scanner](https://swival.dev)

## Preconditions

- The application parses client-controlled address literals using this API.
- Zig safety checks are enabled.

## Proof

The vulnerable parser used narrow index types:

```zig
var parts_i: u8 = 0;
var text_i: u8 = 0;
var digit_i: u8 = 0;
var compress_start: ?u8 = null;
```

When a scope suffix was encountered, parsing executed:

```zig
const name = text[text_i..];
if (name.len == 0) return .incomplete;
interface_name_text = name;
text_i = @intCast(text.len);
continue :state .end;
```

For an input such as:

```text
fe80::1%<padding so total input length is 256 bytes>
```

`@intCast(text.len)` attempts to cast `256` into `u8`. With safety checks enabled, this traps:

```text
panic: integer does not fit in destination type
lib/std/Io/net.zig:577:34: text_i = @intCast(text.len);
```

Reachable public paths include:

- `Ip6Address.Unresolved.parse`
- `Ip6Address.parse`
- `Ip6Address.resolve`
- `IpAddress.parseIp6`
- bracketed IPv6 handling in `IpAddress.parseLiteral`

## Why This Is A Real Bug

The parser accepts untrusted text and should return structured parse failures for invalid or unsupported address literals. Instead, a length-dependent scoped IPv6 literal can trigger a runtime safety trap before normal validation occurs.

The later interface-name validation in `Interface.Name.fromSlice` is not reached because the abort happens inside `Unresolved.parse`. This makes the issue remotely triggerable in applications that parse client-provided address literals.

## Fix Requirement

- Do not store input offsets in `u8`.
- Use `usize` for parser indexes.
- Reject oversized interface names before accepting the scope suffix.
- Preserve normal parse-error behavior instead of allowing a safety trap.

## Patch Rationale

The patch changes parser indexes from `u8` to `usize`, matching slice and length types used by Zig. This removes the truncation/cast hazard for inputs longer than 255 bytes.

It also adds an explicit interface-name length check before storing the scoped name:

```zig
if (name.len > Interface.Name.max_len) return .{ .interface_name_oversized = text_i };
```

This ensures oversized scope names are rejected during parsing, before later resolution code or OS interface-name handling.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/Io/net.zig b/lib/std/Io/net.zig
index c704d8b9e9..14ae05b1e6 100644
--- a/lib/std/Io/net.zig
+++ b/lib/std/Io/net.zig
@@ -511,10 +511,10 @@ pub const Ip6Address = struct {
             }
             // Has to be u16 elements to handle 3-digit hex numbers from compression.
             var parts: [8]u16 = @splat(0);
-            var parts_i: u8 = 0;
-            var text_i: u8 = 0;
-            var digit_i: u8 = 0;
-            var compress_start: ?u8 = null;
+            var parts_i: usize = 0;
+            var text_i: usize = 0;
+            var digit_i: usize = 0;
+            var compress_start: ?usize = null;
             var interface_name_text: ?[]const u8 = null;
             const State = union(enum) { digit, end };
             state: switch (State.digit) {
@@ -575,8 +575,9 @@ pub const Ip6Address = struct {
                         text_i += 1;
                         const name = text[text_i..];
                         if (name.len == 0) return .incomplete;
+                        if (name.len > Interface.Name.max_len) return .{ .interface_name_oversized = text_i };
                         interface_name_text = name;
-                        text_i = @intCast(text.len);
+                        text_i = text.len;
                         continue :state .end;
                     },
                     else => return .{ .invalid_byte = text_i },
```