# File Offset Skips Unsent Bytes On Partial Socket Write

## Classification
- Type: data integrity bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/wasix/sock_send_file.rs:180`
- `lib/wasix/src/syscalls/wasix/sock_send_file.rs:237`
- `lib/virtual-net/src/host.rs:562`
- `lib/virtual-net/src/host.rs:178`

## Summary
`sock_send_file_internal` advances the source file offset immediately after reading a chunk, before confirming how many bytes the socket actually accepted. Because the destination socket path uses a nonblocking `mio::net::TcpStream`, successful partial writes are expected under backpressure. When `send` returns fewer bytes than were read, the unsent suffix is skipped in the file offset, causing dropped bytes in the transmitted stream and corrupting subsequent offset-based reads.

## Provenance
- Verified from the provided reproducer and code-path analysis
- Scanner reference: https://swival.dev

## Preconditions
- Readable input file descriptor
- Socket send path permits partial successful writes
- `sock_send_file_internal` is invoked on that socket
- Backpressure or similar conditions cause `send` to return `bytes_written < data.len()`

## Proof
- `sock_send_file_internal` seeds transmission from the caller-visible file offset in `lib/wasix/src/syscalls/wasix/sock_send_file.rs:180`.
- The implementation reads a buffer from `in_fd` and advances the file offset by the full read length before sending it.
- The send path calls the socket layer with `nonblocking=true` in `lib/wasix/src/syscalls/wasix/sock_send_file.rs:237`.
- The host socket implementation ultimately writes through `m.write(data)` in `lib/virtual-net/src/host.rs:562` on a `mio::net::TcpStream` created via `mio::net::TcpStream::connect(...)` in `lib/virtual-net/src/host.rs:178`.
- A nonblocking TCP stream may legally return a short successful write. In that case, only `bytes_written` is added to `total_written`, while the file offset has already skipped `data.len()`.
- On the next iteration, reading resumes from the advanced offset, so the unsent suffix is never retried and is omitted from the outgoing byte stream.

## Why This Is A Real Bug
The bug does not depend on undefined behavior or an exceptional transport failure. Partial successful writes are normal for nonblocking TCP sockets. The current implementation therefore loses real user data under ordinary backpressure: it reports only the sent byte count, but irreversibly advances the source offset past bytes that were never transmitted. That creates both immediate stream corruption and persistent offset corruption for later operations on the same file descriptor.

## Fix Requirement
The implementation must treat the read buffer as pending until actually sent: advance the source offset by `bytes_written` only, and retry any unsent tail before reading additional file data.

## Patch Rationale
The patch updates `sock_send_file_internal` so offset progression is coupled to confirmed transmission rather than speculative reads. It preserves the current nonblocking send behavior while ensuring short writes cannot create holes in the outgoing stream or desynchronize the backing file offset.

## Residual Risk
None

## Patch
- `021-file-offset-advances-even-when-socket-send-writes-fewer-byte.patch` fixes `lib/wasix/src/syscalls/wasix/sock_send_file.rs` so the source offset is advanced only by bytes actually written and unsent buffer tails are retried before any new file read occurs.