# Vectored UnixStream Writes Omit SIGPIPE Suppression

## Classification

Logic error, medium severity.

## Affected Locations

`library/std/src/os/unix/net/stream.rs:678`

## Summary

`UnixStream` documents that writes to the underlying stream socket use `MSG_NOSIGNAL` to suppress `SIGPIPE` on disconnected sockets. Scalar `write` honors this by calling `send_with_flags(..., MSG_NOSIGNAL)`, but `write_vectored` bypasses that path and delegates to plain vectored file-descriptor writing. On Unix platforms where `MSG_NOSIGNAL` is available, this allows `write_vectored` to terminate the process with `SIGPIPE` instead of returning an `EPIPE` error.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A `UnixStream` peer is disconnected.
- The caller leaves `SIGPIPE` at its default disposition.
- The caller invokes `write_vectored` with at least one nonempty `IoSlice`.

## Proof

At `library/std/src/os/unix/net/stream.rs:674`, scalar writes use:

```rust
self.0.send_with_flags(buf, MSG_NOSIGNAL)
```

At `library/std/src/os/unix/net/stream.rs:678`, vectored writes previously used:

```rust
self.0.write_vectored(bufs)
```

That reaches the socket/file-descriptor vectored path and ultimately plain `writev`, without `MSG_NOSIGNAL`.

A practical reproduction on Linux with the same syscall behavior confirmed:

- `send(fd, ..., MSG_NOSIGNAL)` on one end of a closed Unix `socketpair` returns `-1/EPIPE`.
- `writev(fd, ...)` on the same disconnected socket with default `SIGPIPE` disposition terminates with status `141`, i.e. `128 + SIGPIPE`.

This matches the Rust behavior: `UnixStream::write` returns an error, while the old `UnixStream::write_vectored` path can terminate the process.

## Why This Is A Real Bug

The `UnixStream` documentation states:

> Writes to the underlying socket in `SOCK_STREAM` mode are made with `MSG_NOSIGNAL` flag.

The old vectored implementation violates that invariant. `write_vectored` is part of the standard `io::Write` API for the same stream type, so callers reasonably expect the same `SIGPIPE` suppression as scalar `write`. The behavioral difference is externally observable and can cause unexpected process termination.

## Fix Requirement

Ensure `UnixStream::write_vectored` never performs an unflagged `writev` on disconnected stream sockets. The vectored write path must either use a `sendmsg`/equivalent path with `MSG_NOSIGNAL` or otherwise route writes through `send_with_flags(..., MSG_NOSIGNAL)`.

## Patch Rationale

The patch changes `write_vectored` to use `io::default_write_vectored` with the same flagged scalar send operation used by `write`:

```rust
io::default_write_vectored(|buf| self.0.send_with_flags(buf, MSG_NOSIGNAL), bufs)
```

This preserves the documented `SIGPIPE` suppression invariant for vectored callers by ensuring the actual write syscall uses `MSG_NOSIGNAL`. It also avoids introducing a separate platform-specific `sendmsg` implementation in this location.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/os/unix/net/stream.rs b/library/std/src/os/unix/net/stream.rs
index 30124d96951..56b8202b8ea 100644
--- a/library/std/src/os/unix/net/stream.rs
+++ b/library/std/src/os/unix/net/stream.rs
@@ -678,7 +678,7 @@ fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
     }
 
     fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
-        self.0.write_vectored(bufs)
+        io::default_write_vectored(|buf| self.0.send_with_flags(buf, MSG_NOSIGNAL), bufs)
     }
 
     #[inline]
```