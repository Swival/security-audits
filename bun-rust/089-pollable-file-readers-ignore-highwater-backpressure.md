# Pollable File Readers Ignore Highwater Backpressure

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`src/runtime/webcore/FileReader.rs:810`

## Summary

Socket-backed `FileReader` instances can buffer unbounded data when no stream pull is pending. `on_read_chunk` appends incoming chunks to `self.buffered`, but its highwater backpressure check excludes pollable readers. Sockets are marked pollable, so a malicious peer can continuously send data and force heap growth until process memory exhaustion.

## Provenance

Verified and reproduced from Swival.dev Security Scanner findings: https://swival.dev

## Preconditions

An application exposes a socket-backed `FileReader` to an attacker-controlled peer.

## Proof

- `Lazy::open_file_blob` classifies socket file descriptors as `FileType::Socket` and marks them `pollable`.
- `on_start` propagates the pollable state to the underlying reader.
- When socket data arrives with no pending pull, `on_read_chunk` appends chunks into `self.buffered`.
- The continuation condition previously stopped reads only when `buffered_len + reader_buffer_len >= highwater_mark && !reader_is_pollable()`.
- For sockets, `reader_is_pollable()` is true, so the highwater condition never stops reads.
- `read_socket` continues draining readable socket data into process heap memory, keeping the TCP receive window open and allowing a remote peer to exhaust memory.

## Why This Is A Real Bug

The intended `highwater_mark` limit is bypassed for the exact reader class that can be attacker-fed indefinitely: pollable sockets. Since the runtime keeps consuming socket data into `self.buffered` even when the application is not pulling, kernel/socket backpressure is converted into unbounded userspace buffering. This creates a practical remote memory exhaustion path.

## Fix Requirement

Apply the `highwater_mark` limit to pollable readers as well, or otherwise pause reads once buffered data reaches the highwater threshold.

## Patch Rationale

The patch removes the `!self.reader_is_pollable()` exception from the continuation decision. `on_read_chunk` now returns `false` once `self.buffered.len() + reader_buffer_len` reaches `highwater_mark`, regardless of whether the reader is pollable. This restores backpressure for socket-backed readers while preserving the existing temporary-buffer guard.

## Residual Risk

The pollable exception originated as a "keep pulling pipes so the writer process doesn't block" optimization. Removing it for sockets is correct (sockets have kernel-level flow control). For OS pipes between cooperating processes, returning `false` from `on_read_chunk` pauses polling rather than closing — the writer will block on its `write()` until the consumer pulls, which is the standard backpressure model. No correctness loss; some throughput change for pipe consumers that previously relied on unbounded userspace buffering.

## Patch

```diff
diff --git a/src/runtime/webcore/FileReader.rs b/src/runtime/webcore/FileReader.rs
index 2ac5bf5db4..2133128d40 100644
--- a/src/runtime/webcore/FileReader.rs
+++ b/src/runtime/webcore/FileReader.rs
@@ -798,8 +798,7 @@ impl FileReader {
         let ret = !matches!(
             self.read_inside_on_pull.get(),
             ReadDuringJSOnPullResult::Temporary(_)
-        ) && !(self.buffered.get().len() + reader_buffer_len >= self.highwater_mark
-            && !self.reader_is_pollable());
+        ) && self.buffered.get().len() + reader_buffer_len < self.highwater_mark;
         close_if_needed!();
         ret
     }
```