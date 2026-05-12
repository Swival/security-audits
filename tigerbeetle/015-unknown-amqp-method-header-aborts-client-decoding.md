# Unknown AMQP Method Header Aborts Client Decoding

## Classification

Denial of service, low-to-medium severity. Confidence: certain.

Note: this is the *generator-side* counterpart of finding 004. Finding 004 patches the committed `src/cdc/amqp/spec.zig`; this patch fixes the upstream `src/cdc/amqp/spec_parser.py` so that the next regeneration does not reintroduce the unchecked `@enumFromInt`. Both should land together — fixing only the generated `.zig` would silently regress on the next `spec_parser.py` run; fixing only the generator does nothing for the currently-committed binary. The threat-model and exit-path caveats from finding 004 apply identically: the AMQP peer is operator-configured, and the receive loop in `src/cdc/amqp.zig:771` already calls `fatal` on `error.Unexpected`, so the patch primarily replaces an unchecked enum trap with a well-defined error path rather than preventing termination.

## Affected Locations

`src/cdc/amqp/spec_parser.py:147`

Generated vulnerable output was also observed at:

`src/cdc/amqp/spec.zig:796`

## Summary

`ClientMethod.decode` is generated with an unchecked Zig enum conversion for AMQP method headers received from a server. A malicious or compromised AMQP server can send a syntactically valid method frame with an unknown class/method pair. The generated decoder traps while converting that pair into `ClientMethod.Tag`, aborting the client process before it can return a decode error.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

The finding was reproduced and patched from the supplied evidence.

## Preconditions

- The client decodes AMQP method frames from an untrusted AMQP server.
- The server can send a method frame containing an unknown AMQP class/method pair.

## Proof

The method-frame path decodes server-controlled AMQP input and dispatches it to the generated client method decoder:

- `src/cdc/amqp.zig:791` dispatches decoded frames from server input.
- `src/cdc/amqp.zig:795` handles method frames.
- `src/cdc/amqp/protocol.zig:374` reads the wire `class`/`method` pair.
- `src/cdc/amqp.zig:820` passes that header to `spec.ClientMethod.decode`.
- `src/cdc/amqp/spec_parser.py:148` generated:
  ```zig
  const tag: Tag = @enumFromInt(@as(u32, @bitCast(header)));
  ```
- The committed generated output contained the same unchecked conversion at `src/cdc/amqp/spec.zig:796`.
- `src/cdc/amqp/spec.zig:85` defines `ClientMethod.Tag` as an exhaustive enum of known server-to-client AMQP methods.

An unknown method frame such as:

```text
01 00 00 00 00 00 04 00 01 00 01 ce
```

has a valid frame type, channel, size, payload shape, and frame end byte, but carries unknown method header class `1`, method `1`.

In the project’s default `ReleaseSafe` build mode (`build.zig:109`), `@enumFromInt` traps on that invalid enum value. The trap occurs before `Decoder.Error` can be returned, producing an attacker-triggered client abort.

## Why This Is A Real Bug

The AMQP method header is attacker-controlled when the client connects to an untrusted or malicious server. Unknown class/method values are valid hostile inputs for a decoder and must be rejected as protocol errors, not converted through an unchecked enum cast.

`ClientMethod.Tag` only contains methods known from the AMQP specification. Therefore, arbitrary wire values are not guaranteed to be valid enum members. Using `@enumFromInt` directly on untrusted input makes malformed input control process termination.

## Fix Requirement

The decoder must perform checked enum conversion for the received method header. Unknown headers must return a `Decoder.Error` value instead of trapping or aborting.

## Patch Rationale

The patch changes the generated decoder to use Zig’s checked enum conversion helper:

```zig
const tag: Tag = std.meta.intToEnum(Tag, @as(u32, @bitCast(header))) catch return error.Unexpected;
```

This preserves the existing successful path for known AMQP methods while converting unknown headers into the decoder’s existing error channel. The generated switch remains unchanged and only executes after the header is proven to correspond to a valid `ClientMethod.Tag`.

## Residual Risk

None

## Patch

```diff
diff --git a/src/cdc/amqp/spec_parser.py b/src/cdc/amqp/spec_parser.py
index b8d5bbd8a..5737bae2c 100644
--- a/src/cdc/amqp/spec_parser.py
+++ b/src/cdc/amqp/spec_parser.py
@@ -145,7 +145,7 @@ def client_methods(root):
     print(f"")
     print(f"    pub fn decode(header: MethodHeader, decoder: *Decoder) Decoder.Error!ClientMethod {{")
     print(f"        @setEvalBranchQuota(10_000);")
-    print(f"        const tag: Tag = @enumFromInt(@as(u32, @bitCast(header)));")
+    print(f"        const tag: Tag = std.meta.intToEnum(Tag, @as(u32, @bitCast(header))) catch return error.Unexpected;")
     print(f"        const value: ClientMethod = switch (tag) {{")
     print(f"            inline else => |tag_comptime| value: {{")
     print(f"                const Method = std.meta.TagPayload(ClientMethod, tag_comptime);")
```