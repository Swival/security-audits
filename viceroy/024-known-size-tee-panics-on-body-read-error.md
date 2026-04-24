# Known-size tee panics on body read error

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/body_tee.rs:67`
- `src/body_tee.rs:70`
- `src/body_tee.rs:73`

## Summary
`tee` treats an exact `size_hint` as proof that buffering cannot fail, then calls `hyper::body::to_bytes(hyper_body).await.expect(...)`. For known-size bodies that later error during read, this converts a normal body read failure into a panic instead of returning two bodies that both surface the same error.

## Provenance
- Verified from the provided reproducer and code path in `src/body_tee.rs`
- Dependency context comes from `Cargo.toml:109` pinning `hyper = "=0.14.26"`
- Reference: https://swival.dev

## Preconditions
- Input body reports `HttpBody::size_hint(&hyper_body).exact().is_some()`
- The body later fails while being fully buffered, such as an HTTP/1 peer declaring `Content-Length` and disconnecting before sending all bytes

## Proof
At `src/body_tee.rs:67`, `tee` checks whether the incoming body has an exact size hint and takes the eager-buffering path. In that branch, `src/body_tee.rs:70` and `src/body_tee.rs:73` call `hyper::body::to_bytes(hyper_body).await.expect("Failed to buffer known-size body")`.

This assumption is false under the pinned `hyper` version. With `hyper = "=0.14.26"`, an HTTP/1 body can report an exact size from `Content-Length` and still fail during reads if the peer sends fewer bytes than promised and disconnects. In that case `to_bytes()` returns `Err` and the `expect(...)` panics immediately.

The reproducer confirms this path is reachable and practical: a client advertises `Content-Length: N`, sends fewer than `N` bytes, then closes the connection. `tee` enters the known-size branch, `to_bytes()` errors with the length decoder failure, and the panic is triggered.

## Why This Is A Real Bug
This is not a theoretical inconsistency in metadata; it is a reachable network failure mode for normal HTTP/1 traffic. `size_hint().exact()` only reflects declared framing, not guaranteed delivery. Panicking on that error changes a recoverable request-body failure into process-level failure in the request handler, which is a materially different and more severe outcome.

## Fix Requirement
Replace the `expect(...)` in the exact-size buffering branch with error-preserving handling. On buffering failure, return two bodies that both yield the cloned read error instead of panicking.

## Patch Rationale
The patch removes the panic path and preserves existing `tee` semantics by converting the buffered-read failure into duplicated erroring bodies. This keeps the optimization for successfully buffered known-size bodies while restoring ordinary error propagation for truncated or otherwise failing inputs.

## Residual Risk
None

## Patch
- `024-known-size-tee-panics-on-body-read-error.patch` removes the `expect(...)`-based panic path in `src/body_tee.rs`
- The known-size branch now handles `to_bytes(...).await` errors explicitly and returns two bodies that each surface the same cloned error
- Successful exact-size buffering behavior remains unchanged