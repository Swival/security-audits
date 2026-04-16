# Write path drops completion on synchronous `uv_write` error

## Classification
- Type: error-handling bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/common/socket/uv-binding.c.h:219`
- `lib/common/socket/uv-binding.c.h:265`
- `lib/common/socket.c:910`
- `lib/common/socket/uv-binding.c.h:297`
- `include/h2o/socket.h:550`

## Summary
`do_write` and `do_ssl_write` submit writes through `uv_write` but do not check its immediate return value. When `uv_write` fails synchronously, libuv does not invoke the completion callback, so the code never disposes queued buffers and never delivers the caller's write completion. This leaves the socket stuck in a logical writing state and can retain write-side resources until teardown.

## Provenance
- Verified from the supplied finding and reproducer
- Reproduced behavior is consistent with libuv's synchronous-error contract for `uv_write`
- Reference: https://swival.dev

## Preconditions
- `uv_write` returns an immediate nonzero error for a submitted write attempt
- A caller reaches the TCP or SSL write path through `h2o_socket_write`

## Proof
- `h2o_socket_write` forwards caller-controlled buffers into the uv-backed write path at `lib/common/socket.c:910` and `lib/common/socket/uv-binding.c.h:297`
- `do_write` calls `uv_write` at `lib/common/socket/uv-binding.c.h:219` without checking the return code
- `do_ssl_write` does the same at `lib/common/socket/uv-binding.c.h:265`
- On synchronous errors such as `UV_EBADF`, `UV_EPIPE`, `UV_EINVAL`, or `UV_ENOMEM`, libuv returns immediately and does not run `on_do_write_complete` / `on_ssl_write_complete`
- Cleanup and callback delivery are only performed from those completion handlers, so the write never completes from the caller's perspective
- The reproduced practical trigger is `UV_ENOMEM` on the non-SSL path, where a large caller-controlled `bufcnt` can force libuv to allocate an internal iovec copy and fail immediately

## Why This Is A Real Bug
The implementation assumes every submitted write eventually reaches the completion callback. That assumption is false for synchronous `uv_write` failures. Because write state teardown, callback delivery, and some buffer release paths are completion-handler-only, ignoring the return value creates a permanent state machine stall rather than a transient error. This is externally reachable from normal write APIs and directly affects correctness and resource lifetime.

## Fix Requirement
Check the return value of each `uv_write` call. On nonzero return, execute the same completion effects that would have happened via libuv callback, with the error propagated immediately or through an equivalent deferred completion path.

## Patch Rationale
The patch in `021-write-path-ignores-uv-write-failure-and-loses-completion.patch` should make synchronous submission failure observable to the existing write-completion flow instead of waiting for a callback that libuv will never issue. That preserves callback delivery, clears `_cb.write`, and releases write-associated buffers on both plain and SSL paths.

## Residual Risk
None

## Patch
- Added synchronous `uv_write` error handling in `lib/common/socket/uv-binding.c.h`
- Ensured both plain and SSL write paths complete with error when submission fails immediately
- Preserved existing completion semantics by routing failure through the same logical cleanup/callback path
- Eliminated the lost-completion condition that left sockets permanently marked as writing