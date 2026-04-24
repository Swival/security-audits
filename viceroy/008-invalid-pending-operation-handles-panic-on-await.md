# Invalid pending-operation handles panic on await

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/component/compute/kv_store.rs:64`
- `src/component/compute/kv_store.rs:76`
- `src/component/compute/kv_store.rs:109`
- `src/component/compute/kv_store.rs:128`
- `src/component/compute/kv_store.rs:147`

## Summary
`await_lookup`, `await_insert`, `await_delete`, and `await_list` accepted guest-controlled pending-operation handles and unwrapped session lookups that can fail. A guest can pass a live but wrong-kind `pollable` handle, such as a `new-ready` handle, causing the host to panic instead of returning a typed invalid-handle error.

## Provenance
- Verified from the provided reproduction and code-path analysis in `src/component/compute/kv_store.rs`, `src/session.rs:879`, `src/session.rs:897`, `src/session.rs:1180`, and `src/session/async_item.rs:152`
- Scanner source: https://swival.dev

## Preconditions
- Guest calls an `await_*` function with a stale, already-consumed, dropped, or wrong-kind pending handle
- The handle passes component resource validation as a live `pollable` alias

## Proof
- In `src/component/compute/kv_store.rs:64`, guest input reaches `await_lookup`, is converted to a `KvStoreLookupHandle`, then passed into `session_mut().take_pending_kv_lookup(handle).unwrap()`
- `take_pending_kv_lookup` returns an error for invalid or wrong-kind handles rather than a pending item, including `InvalidPendingKvLookupHandle(...)`, as evidenced at `src/session.rs:879` and `src/session.rs:897`
- A `new-ready` handle is stored as `AsyncItem::Ready`, not `PendingKvLookup`, at `src/session/async_item.rs:152` and `src/session.rs:1180`
- Passing that live `pollable` into `await_lookup` reaches the unchecked unwrap at `src/component/compute/kv_store.rs:76` and panics
- The same unchecked pattern exists at `src/component/compute/kv_store.rs:109`, `src/component/compute/kv_store.rs:128`, and `src/component/compute/kv_store.rs:147` for insert, delete, and list

## Why This Is A Real Bug
This is guest-triggerable denial of service. The failing path does not depend on forging arbitrary resources; it is reachable with a valid live `pollable` resource of the wrong async-item kind. Because the host panics on malformed but type-valid guest input, the behavior is externally triggerable and violates expected error handling.

## Fix Requirement
Replace each `unwrap()` on pending-operation retrieval with checked error propagation and return the existing typed invalid-handle error for lookup, insert, delete, and list await paths.

## Patch Rationale
The patch removes panic-on-invalid-handle behavior and aligns `await_*` with the session layer's existing typed handle validation. This preserves normal behavior for valid pending operations while converting malformed handle use into ordinary guest-visible errors.

## Residual Risk
None

## Patch
- Patch file: `008-invalid-pending-operation-handles-panic-on-await.patch`
- The patch replaces unchecked pending-handle unwraps in `src/component/compute/kv_store.rs` with checked lookups that propagate typed invalid-handle errors for all four await entrypoints