# MSG_TRUNC receive length slices past buffer

## Classification

Denial of service, medium severity.

## Affected Locations

- `lib/std/Io/Uring.zig` — `netReceive` SUCCESS arm (`remaining_data_buffer[0..@intCast(completion.result)]`).
- `lib/std/Io/Threaded.zig` — `netReceivePosix` SUCCESS arm (`data_buffer[0..@intCast(rc)]`); the
  Threaded/Posix backend sets `MSG.TRUNC` the same way and has the identical unclamped slice, so
  the fix covers both backends.

## Summary

`netReceive` submits `RECVMSG` with `linux.MSG.TRUNC` when `ReceiveFlags.trunc` is set. On Linux datagram sockets, `MSG_TRUNC` can cause `recvmsg` to return the full datagram length, not the number of bytes copied into the supplied iovec. The returned length was used directly as a slice bound into `remaining_data_buffer`, allowing a remote oversized datagram to trigger an out-of-bounds slice trap when the caller supplied an undersized receive buffer.

## Provenance

Verified and reproduced from Swival security analysis.

Scanner: [Swival.dev Security Scanner](https://swival.dev)

Confidence: certain.

## Preconditions

- Application uses the `Io.Uring` backend.
- Application receives datagrams through `.net_receive`.
- Caller sets `ReceiveFlags.trunc`.
- Caller supplies a `data_buffer` smaller than an attacker-controlled datagram.
- Remote attacker can send datagrams to the receiving socket.

## Proof

The receive path sets `MSG_TRUNC` when requested:

```zig
.rw_flags = linux.MSG.NOSIGNAL |
    @as(u32, if (flags.oob) linux.MSG.OOB else 0) |
    @as(u32, if (flags.peek) linux.MSG.PEEK else 0) |
    @as(u32, if (flags.trunc) linux.MSG.TRUNC else 0),
```

After completion, the result is used directly as the slice end:

```zig
const data = remaining_data_buffer[0..@intCast(completion.result)];
```

For a datagram of length `L` received into a buffer of length `B`, Linux may return `completion.result == L` with `MSG_TRUNC`, while only `B` bytes were copied. If `L > B`, the slice end exceeds `remaining_data_buffer.len`, causing a bounds trap/panic in safety-checked builds and aborting the receiver process.

## Why This Is A Real Bug

The length returned by `recvmsg(MSG_TRUNC)` is not guaranteed to be bounded by the iovec length for datagram sockets. The code treated that returned length as copied-buffer length. A remote sender controls datagram size, so an oversized datagram can reliably make the receiver attempt an invalid slice. This is a practical remote denial of service for affected applications.

## Fix Requirement

Clamp the sliced data length to `remaining_data_buffer.len` before constructing the slice. The reported truncation condition remains available through message flags, but the returned `data` slice must only cover bytes actually addressable in the provided buffer.

## Patch Rationale

The patch bounds the completion result by the remaining destination buffer length:

```zig
@min(@as(usize, @intCast(completion.result)), remaining_data_buffer.len)
```

This preserves normal behavior when the result fits and safely handles `MSG_TRUNC` full-datagram-length returns when the datagram is larger than the supplied buffer.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/Io/Threaded.zig b/lib/std/Io/Threaded.zig
index 90d74d4b37..5580d2f117 100644
--- a/lib/std/Io/Threaded.zig
+++ b/lib/std/Io/Threaded.zig
@@ -13048,7 +13048,7 @@ fn netReceivePosix(
         switch (posix.errno(rc)) {
             .SUCCESS => {
                 syscall.finish();
-                const data = data_buffer[0..@intCast(rc)];
+                const data = data_buffer[0..@min(@as(usize, @intCast(rc)), data_buffer.len)];
                 message.* = .{
                     .from = addressFromPosix(&storage),
                     .data = data,
diff --git a/lib/std/Io/Uring.zig b/lib/std/Io/Uring.zig
index 9184cd5741..67a178f940 100644
--- a/lib/std/Io/Uring.zig
+++ b/lib/std/Io/Uring.zig
@@ -5116,7 +5116,7 @@ fn netReceive(
         const completion = cancel_region.completion();
         switch (completion.errno()) {
             .SUCCESS => {
-                const data = remaining_data_buffer[0..@intCast(completion.result)];
+                const data = remaining_data_buffer[0..@min(@as(usize, @intCast(completion.result)), remaining_data_buffer.len)];
                 data_i += data.len;
                 message.* = .{
                     .from = addressFromPosix(&storage),
```
