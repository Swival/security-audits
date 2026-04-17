# AsyncReadStream readiness panics on worker channel disconnect

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `crates/wasi/src/p2/pipe.rs:161`

## Summary
`AsyncReadStream::poll_ready` treats a closed worker channel as impossible and panics. If the spawned worker task exits before sending a terminal message, `receiver.poll_recv(cx)` returns `Poll::Ready(None)` and the caller awaiting readiness crashes instead of receiving a `StreamError`.

## Provenance
- Verified by reproduction against the reported code path
- Reference: Swival Security Scanner - https://swival.dev

## Preconditions
- `AsyncReadStream` is constructed from an `AsyncRead` implementation whose worker task can terminate before emitting a final message
- In practice, a caller-supplied reader that panics during `poll_read` is sufficient

## Proof
A focused reproducer wrapped a custom panic-capable `AsyncRead` in `AsyncReadStream` and awaited `ready()`. The worker task died first, the internal channel closed, `poll_ready` observed `Poll::Ready(None)` at `crates/wasi/src/p2/pipe.rs:161`, and the caller panicked on the `"should be impossible"` branch. The temporary test was then removed after verification.

## Why This Is A Real Bug
This is externally reachable because `AsyncReadStream::new` is public and generic over arbitrary async readers. A misbehaving or panic-capable reader can crash the process through the readiness path alone. The synchronous path already handles the analogous disconnect condition by returning `StreamError::Trap` at `crates/wasi/src/p2/pipe.rs:250`, confirming the panic is unintended behavior rather than an accepted invariant.

## Fix Requirement
Replace the impossible-case panic in `poll_ready` with normal error handling: mark the stream closed and return a `StreamError` such as `Trap` or `Closed`.

## Patch Rationale
The patch in `005-asyncreadstream-panics-if-worker-sender-exits-unexpectedly.patch` converts the closed-channel branch into an error result instead of panicking. This aligns readiness handling with the existing disconnected-channel behavior in the synchronous read path and preserves process stability when the worker exits early.

## Residual Risk
None

## Patch
- File: `005-asyncreadstream-panics-if-worker-sender-exits-unexpectedly.patch`
- Change: replace the `panic!("should be impossible")` path in `AsyncReadStream::poll_ready` with closed-state/error propagation so callers receive a `StreamError` rather than a process-level panic