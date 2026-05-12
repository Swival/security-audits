# Unknown AMQP Method Traps Client Decoder

## Classification

Denial of service, low-to-medium severity. Confidence: certain.

Threat model note: like finding 003, the AMQP peer is an operator-configured component, not an arbitrary network attacker. The CDC daemon already terminates with `fatal()` on `error.Unexpected` (see `process` in `src/cdc/amqp.zig`), so the patched and unpatched code both end in process exit. The improvement is to replace `@enumFromInt` (illegal behavior on unknown tags — safety panic in `ReleaseSafe`, undefined in `ReleaseFast`) with the codebase's established `intToEnum`/`Decoder.Error.Unexpected` pattern (see `read_enum` in `src/cdc/amqp/protocol.zig:290-298` for the same pattern already in use). This makes the error path well-defined and attributable rather than relying on a runtime trap.

## Affected Locations

`src/cdc/amqp/spec.zig:779`

## Summary

`ClientMethod.decode` converts a peer-supplied AMQP method header into `ClientMethod.Tag` with an unchecked enum conversion. If an attacker-controlled peer sends an unknown class/method tuple, Zig triggers an invalid enum conversion safety trap instead of returning a decoder error, aborting the client process.

## Provenance

Verified finding from Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Client decodes method frames from an attacker-controlled AMQP peer, such as a malicious AMQP server or network peer.

## Proof

A method frame with a valid frame envelope but unknown method tuple reproduces the crash:

```text
01 00 00 00 00 00 04 00 0a 00 63 ce
```

This encodes:

```text
type=method, channel=0, size=4, class=10, method=99, frame-end=0xce
```

The decode path is:

```text
receive_callback -> process -> process_method -> ClientMethod.decode
```

At `src/cdc/amqp/spec.zig:796`, the original code performs:

```zig
const tag: Tag = @enumFromInt(@as(u32, @bitCast(header)));
```

`ClientMethod.Tag` only contains known client-side AMQP methods. The tuple `{ class = 10, method = 99 }` is not a valid tag. In `ReleaseSafe`, this invalid enum conversion triggers a Zig safety panic/abort before `decoder.read_frame_end()` is reached.

## Why This Is A Real Bug

The method header is attacker-controlled input from the AMQP peer. Decoding untrusted protocol bytes must reject unknown methods through a recoverable `Decoder.Error`. Instead, the unchecked `@enumFromInt` converts hostile input into a closed enum and can terminate the process. This is externally triggerable denial of service.

## Fix Requirement

Replace unchecked enum conversion with checked tag lookup. Unknown method class/id values must return a decoder/frame/syntax error instead of trapping.

## Patch Rationale

The patch uses `std.meta.intToEnum` to validate the integer against `ClientMethod.Tag`. If no matching tag exists, decode returns `error.Unexpected`. Known tags continue through the existing generated payload decode switch unchanged.

## Residual Risk

None

## Patch

```diff
diff --git a/src/cdc/amqp/spec.zig b/src/cdc/amqp/spec.zig
index f0927ff9a..183a408e8 100644
--- a/src/cdc/amqp/spec.zig
+++ b/src/cdc/amqp/spec.zig
@@ -793,7 +793,7 @@ pub const ClientMethod = union(ClientMethod.Tag) {
 
     pub fn decode(header: MethodHeader, decoder: *Decoder) Decoder.Error!ClientMethod {
         @setEvalBranchQuota(10_000);
-        const tag: Tag = @enumFromInt(@as(u32, @bitCast(header)));
+        const tag = std.meta.intToEnum(Tag, @as(u32, @bitCast(header))) catch return error.Unexpected;
         const value: ClientMethod = switch (tag) {
             inline else => |tag_comptime| value: {
                 const Method = std.meta.TagPayload(ClientMethod, tag_comptime);
```