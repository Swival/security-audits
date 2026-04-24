# Invalid pending request handle panics await_response

## Classification
- Type: error-handling bug
- Severity: high
- Confidence: certain

## Affected Locations
- `src/component/compute/http_req.rs:108`
- `src/component.rs:29`
- `src/component/compute/error.rs:33`
- `/core.rs:2562`

## Summary
`await_response` trusts a guest-controlled `Resource<PendingRequest>` and calls `session_mut().take_pending_request(h.into()).unwrap()`. If the handle is stale, already consumed, or arbitrary, lookup returns `None` and `unwrap()` panics, causing a host trap instead of a typed API failure.

## Provenance
- Verified from the provided reproducer and source review
- Reproduced against the component path described in the report
- Scanner reference: https://swival.dev

## Preconditions
- A guest can call `await_response` with a stale, already-consumed, or invalid pending request handle
- The component import remains non-trappable, so panics escape as host traps

## Proof
- `src/component/compute/http_req.rs:108` calls `session_mut().take_pending_request(h.into()).unwrap()`
- `take_pending_request(...)` returns `None` when the pending handle does not exist
- `/core.rs:2562` reconstructs a component resource from any guest-supplied integer via `unsafe { http_req::PendingResponse::from_handle(pending_req_handle) }`
- A guest can therefore pass an arbitrary integer to `fastly_http_req#pending_req_wait`, or reuse a handle after one successful wait, reaching the `unwrap()` on a missing entry
- `src/component.rs:29` imports `fastly:compute/http-req.await-response` without `trappable`, so the panic propagates as a host trap/abort rather than a typed `ErrorWithDetail`

## Why This Is A Real Bug
The failure is reachable from guest input and converts an invalid-handle condition into a process-level trap. This is a correctness and availability issue: callers cannot recover through the declared API surface, and a malformed or repeated handle aborts execution instead of returning an ordinary error.

## Fix Requirement
Replace the `unwrap()` on pending-request removal with explicit invalid-handle handling that returns the component’s typed error result before awaiting the receiver.

## Patch Rationale
The patch should make missing pending-request entries follow the normal API error path rather than panicking. This preserves the contract of `await_response` for malformed or reused handles and blocks guest-triggered host traps at the point of use.

## Residual Risk
None

## Patch
- Patch file: `014-invalid-pending-request-handle-panics-await-response.patch`
- Required change: in `src/component/compute/http_req.rs`, replace the direct `unwrap()` after `take_pending_request(h.into())` with explicit error propagation for an invalid or stale handle before continuing to await the response