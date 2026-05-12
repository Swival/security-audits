# Unsupported AMQP Field Tag Terminates Process

## Classification

Denial of service, low-to-medium severity. Confidence: certain.

Same threat model and trade-off as findings 003 and 004: the AMQP peer is an operator-configured broker, and the receive loop in `src/cdc/amqp.zig:771` still calls `fatal("Invalid command received.", .{})` when it catches `error.Unexpected`. So the process still exits in both the patched and unpatched code. The improvement is to route the unsupported-tag case through the established decoder-error path (`Decoder.Error.Unexpected`, used consistently elsewhere), giving a single, attributable termination site rather than an ad-hoc `fatal` deep inside the table decoder. This is a code-cleanliness and defense-in-depth fix more than a DoS-preventing one — but it is the right shape if the project later wants to recover from broker protocol errors via reconnect rather than process exit.

## Affected Locations

`src/cdc/amqp/protocol.zig:352`

## Summary

A malicious AMQP peer can send a field table containing a valid but unsupported AMQP field-value tag. During client-side table iteration, the decoder calls `fatal(...)`, which exits the whole process with a nonzero status. Peer-controlled input therefore causes deterministic AMQP client process termination instead of a recoverable decode error.

## Provenance

Verified finding from Swival.dev Security Scanner: https://swival.dev

## Preconditions

- The client decodes a peer-supplied AMQP field table.
- The peer can place one unsupported AMQP field-value tag in that table.
- The unsupported tag is one of `L`, `A`, `f`, `d`, `D`, or `x`.

## Proof

Reachable path:

- `receive_callback()` parses peer bytes via `process()` and `process_method()`.
- `spec.ClientMethod.decode()` reads `connection_start.server_properties` as a `Decoder.Table`.
- `connect_dispatch()` calls `log_table("server_properties", args.server_properties)`.
- `log_table()` iterates the table.
- `Decoder.Table.Iterator.next()` calls `Decoder.read_field()`.
- `Decoder.read_field()` decodes the byte as `FieldValueTag`.
- For valid enum tags `L`, `A`, `f`, `d`, `D`, or `x`, the switch reaches the unsupported arm.
- Before the patch, that arm calls `fatal("AMQP type '{c}' not supported.", .{@intFromEnum(tag)})`.
- `fatal()` logs and calls `std.process.exit(status)`.

Relevant code paths:

- `src/cdc/amqp/protocol.zig:228`
- `src/cdc/amqp/protocol.zig:334`
- `src/cdc/amqp/protocol.zig:350`
- `src/cdc/amqp.zig:279`
- `src/cdc/amqp.zig:1174`
- `src/cdc/amqp/protocol.zig:795`

## Why This Is A Real Bug

The unsupported field tags are valid AMQP tags represented in `FieldValueTag`, so `read_enum(FieldValueTag)` accepts them. The failure occurs after validation, inside normal decode logic for peer-controlled table contents. Because `fatal()` is process-global termination, a single crafted table field can deny service to the AMQP client process. Decode errors are already modeled by `Decoder.Error.Unexpected`, making process exit unnecessary and inconsistent with malformed-input handling.

## Fix Requirement

Return `error.Unexpected` for unsupported decoded AMQP field tags instead of calling `fatal(...)`.

## Patch Rationale

The patch changes only the decoder-side unsupported-tag behavior. Unsupported peer-supplied field values now propagate through the existing `Decoder.Error` path, allowing callers to reject the frame/connection without terminating the entire process.

The encoder-side `fatal(...)` behavior is not changed by this patch because encoder input is local/application-controlled rather than directly peer-supplied in the reproduced path.

## Residual Risk

None

## Patch

```diff
diff --git a/src/cdc/amqp/protocol.zig b/src/cdc/amqp/protocol.zig
index dd83dd954..355b7e3b0 100644
--- a/src/cdc/amqp/protocol.zig
+++ b/src/cdc/amqp/protocol.zig
@@ -353,7 +353,7 @@ pub const Decoder = struct {
             .not_implemented_double,
             .not_implemented_decimal,
             .not_implemented_byte_array,
-            => fatal("AMQP type '{c}' not supported.", .{@intFromEnum(tag)}),
+            => return error.Unexpected,
         };
         assert(value == tag);
         return value;
```