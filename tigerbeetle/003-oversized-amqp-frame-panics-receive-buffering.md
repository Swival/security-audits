# Oversized AMQP Frame Panics Receive Buffering

## Classification

Denial of service, low-to-medium severity. Confidence: certain.

Threat model note: the CDC client connects to an AMQP broker configured by the operator, so the broker is part of the trusted topology rather than a hostile network peer. The realistic attacker is either a compromised broker or anyone able to inject bytes into the TCP stream between TigerBeetle and the broker (e.g. unencrypted AMQP on a hostile network). The CDC pipeline already calls `fatal()` and exits on many broker-side protocol errors, so the practical change here is replacing an assertion-trip deep in receive buffering with a precise, attributable error message at the AMQP layer — defense in depth and observability, more than a brand-new DoS vector.

## Affected Locations

`src/cdc/amqp.zig:867`

## Summary

A malicious AMQP broker can advertise a frame payload larger than the client's receive buffer. When assertions are enabled, the client preserves the entire full buffer as unconsumed data and trips an assertion in receive buffering, panicking the process and stopping AMQP/CDC message handling.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

The finding was reproduced and patched from the provided source and patch evidence.

## Preconditions

- The client connects to an AMQP broker controlled by an attacker.
- Assertions are enabled.
- The broker sends an AMQP frame header with a valid type/channel and a declared payload size larger than the client's receive buffer can hold.

## Proof

`receive_callback` passes broker-controlled bytes into `ReceiveBuffer.end_receive`, then repeatedly calls `process` while frames are available.

For an oversized first frame:

- `process` reads the AMQP frame header.
- `Decoder.read_body()` or `Decoder.read_header()` returns `error.BufferExhausted` because the declared frame size cannot fit in the current decoder buffer.
- No complete frame is processed, so `processed_index_last` remains `0`.
- `receive_callback` calls `end_decode(0)`.
- If the receive buffer is full, `end_decode(0)` treats the entire buffer as `remaining`.
- `remaining.len == self.buffer.len`, violating `assert(remaining.len < self.buffer.len)`.
- The client panics.

The reproduced path identifies the relevant behavior at `src/cdc/amqp.zig:762`, `src/cdc/amqp.zig:764`, `src/cdc/amqp.zig:766`, `src/cdc/amqp.zig:1086`, `src/cdc/amqp.zig:1098`, and `src/cdc/amqp.zig:1099`.

## Why This Is A Real Bug

The AMQP broker controls the TCP bytes received by the client. A hostile broker can send a frame header with a declared payload size that exceeds the client's receive buffer. Because parsing returns `error.BufferExhausted` before any full frame is consumed, the receive buffer cannot make progress and hits an assertion when full.

This is not merely malformed local input: it is network-reachable from the connected broker and causes the client process to panic, terminating AMQP message handling.

## Fix Requirement

Reject AMQP frames whose declared payload size cannot fit in the receive buffer before preserving unconsumed bytes.

The size check must account for:

- AMQP frame header length.
- Declared frame payload length.
- AMQP frame-end byte.

## Patch Rationale

The patch adds a bound check immediately after reading the frame header in `Client.process`.

If `frame_header.size` exceeds the maximum payload that can fit in the receive buffer after reserving space for `Encoder.FrameHeader.size_total` and `protocol.FrameEnd`, the client calls `fatal("AMQP frame exceeds receive buffer.", .{})`.

This prevents the decoder from repeatedly treating an impossible oversized frame as incomplete input and prevents `ReceiveBuffer.end_decode(0)` from preserving a full buffer.

## Residual Risk

None

## Patch

```diff
diff --git a/src/cdc/amqp.zig b/src/cdc/amqp.zig
index 64e5df298..0072214c7 100644
--- a/src/cdc/amqp.zig
+++ b/src/cdc/amqp.zig
@@ -790,6 +790,11 @@ pub const Client = struct {
 
     fn process(self: *Client, decoder: *Decoder) Decoder.Error!void {
         const frame_header = try decoder.read_frame_header();
+        if (@as(usize, frame_header.size) >
+            self.receive_buffer.buffer.len - Encoder.FrameHeader.size_total - @sizeOf(protocol.FrameEnd))
+        {
+            fatal("AMQP frame exceeds receive buffer.", .{});
+        }
         switch (frame_header.type) {
             .method => {
                 const method_header = try decoder.read_method_header();
```