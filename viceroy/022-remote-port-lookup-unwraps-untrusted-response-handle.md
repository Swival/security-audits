# Remote port lookup unwraps untrusted response handle

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/component/compute/http_resp.rs:281`

## Summary
- `get_remote_port` dereferences a guest-controlled response handle with `self.session().response_parts(resp_handle.into()).unwrap()`.
- If the guest passes an invalid or previously closed handle, `response_parts` returns `Err` and `unwrap()` traps the host instead of reporting absence.
- This diverges from adjacent fallible accessors and from the older wiggle ABI behavior, which returns `Badf` or `None` for bad handles.

## Provenance
- Verified from the provided reproducer and code path in `src/component/compute/http_resp.rs:281`.
- Comparative behavior confirmed against `src/wiggle_abi/resp_impl.rs:244` and `src/wiggle_abi/resp_impl.rs:282`.
- Scanner reference: https://swival.dev

## Preconditions
- Guest supplies an invalid response handle to the remote port accessor.
- Or guest closes a valid response first, then reuses the stale numeric handle.

## Proof
- `resp_handle` is guest-controlled input.
- In `get_remote_port`, that value flows directly into `self.session().response_parts(resp_handle.into()).unwrap()`.
- The reproducer closes a response via `fastly_http_resp#close` or uses an arbitrary integer, then calls `fastly_http_resp#get_addr_dest_port`.
- The adapter rewraps the integer as a resource and invokes component `get_remote_port`.
- `response_parts` returns `Err(InvalidResponseHandle)` for the stale or invalid handle, and `unwrap()` panics, causing a trap instead of returning `None`.

## Why This Is A Real Bug
- The fault is reachable from normal guest-controlled API input without memory corruption or races.
- Invalid and stale handles are expected error cases for hostcall-style interfaces and must not abort the host.
- The same API family already treats missing state as fallible, and the legacy ABI returns `Badf`/`None`, confirming the intended contract.
- A malicious or buggy guest can reliably convert a recoverable bad-handle condition into host termination for this accessor.

## Fix Requirement
- Replace the `unwrap()`-based response handle lookup with fallible handling.
- Return `None` when the response handle is invalid or closed, matching the accessor family’s expected behavior.

## Patch Rationale
- The patch updates `get_remote_port` to handle `response_parts(...)` failure explicitly instead of panicking.
- Returning `None` preserves the interface contract for absent remote-port metadata and aligns behavior with neighboring fallible accessors and the wiggle ABI.

## Residual Risk
- None

## Patch
- Patched in `022-remote-port-lookup-unwraps-untrusted-response-handle.patch`.
- The change removes the panic path in `src/component/compute/http_resp.rs` by replacing `unwrap()` with fallible handle lookup and `None` on invalid handles.