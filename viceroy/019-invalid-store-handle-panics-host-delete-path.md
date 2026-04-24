# Invalid store handle panics host delete path

## Classification
- Type: error-handling bug
- Severity: high
- Confidence: certain

## Affected Locations
- `src/wiggle_abi/obj_store_impl.rs:125`

## Summary
`delete_async` accepted a guest-controlled `ObjectStoreHandle` and dereferenced it with `self.get_kv_store_key(store.into()).unwrap().clone()`. An unknown, forged, or stale handle therefore caused a host-side panic instead of returning a guest-visible error status.

## Provenance
- Verified from the provided reproducer and source analysis
- Scanner source: https://swival.dev

## Preconditions
- Guest can call `delete_async` with an arbitrary `ObjectStoreHandle`

## Proof
- `delete_async` read the handle and immediately executed `self.get_kv_store_key(store.into()).unwrap().clone()` in `src/wiggle_abi/obj_store_impl.rs:125`
- `get_kv_store_key(...)` returns `None` for an invalid handle
- Because `unwrap()` was used, the invalid handle path panicked before any delete task or error result was produced
- The reproducer confirmed the panic propagates through the request path rather than becoming a `fastly_status` error

## Why This Is A Real Bug
The hostcall boundary must treat guest input as untrusted. Other object-store entry points validate handles and map failure into `Result` errors, but `delete_async` did not. This created a reachable panic from attacker-controlled input, causing request-path denial of service instead of normal error handling.

## Fix Requirement
Replace the `unwrap()` on the store lookup with checked error propagation that converts an invalid handle into the existing guest-visible error result.

## Patch Rationale
The patch changes `delete_async` to validate the store handle before use and return an error when lookup fails, matching the defensive behavior already used by related handle-consuming paths. This removes the panic condition without changing valid-handle behavior.

## Residual Risk
None

## Patch
- `019-invalid-store-handle-panics-host-delete-path.patch` updates `src/wiggle_abi/obj_store_impl.rs` to replace the unchecked `unwrap()` with explicit invalid-handle error handling
- Valid store handles continue through the existing delete flow unchanged
- Invalid or stale handles now fail closed with a normal hostcall error instead of unwinding the host path