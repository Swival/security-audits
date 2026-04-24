# Invalid store handle panics KV hostcalls

## Classification
- Type: error-handling bug
- Severity: high
- Confidence: certain

## Affected Locations
- `src/wiggle_abi/kv_store_impl.rs:42`
- `src/component/compute/kv_store.rs:193`
- `src/component/compute/kv_store.rs:228`
- `src/component/compute/kv_store.rs:276`
- `src/component/compute/kv_store.rs:302`

## Summary
Guest-controlled `KvStoreHandle` values reached KV hostcalls and component-model KV methods, where they were immediately dereferenced with `unwrap()`. An invalid or stale handle therefore triggered a panic/trap instead of returning a structured handle-validation error.

## Provenance
- Verified from the supplied finding and reproducer evidence
- Reproduced against the listed call sites in `src/wiggle_abi/kv_store_impl.rs:42` and `src/component/compute/kv_store.rs:193`
- Scanner reference: `https://swival.dev`

## Preconditions
- Guest can call KV hostcalls with an arbitrary or stale store handle

## Proof
- `lookup`, `insert`, `delete`, and `list` in `src/wiggle_abi/kv_store_impl.rs` accepted guest-controlled `store: KvStoreHandle` and called `self.get_kv_store_key(store).unwrap()` or `unwrap().clone()`.
- The component-model KV methods in `src/component/compute/kv_store.rs:193`, `src/component/compute/kv_store.rs:228`, `src/component/compute/kv_store.rs:276`, and `src/component/compute/kv_store.rs:302` performed the same unchecked `unwrap()` on `self.session.get_kv_store_key(...)`.
- If `get_kv_store_key` returned `None`, execution panicked before normal hostcall error mapping.
- The reproducer confirmed this escapes as a trap rather than a recoverable `Error`, matching the host execution behavior described via `src/wiggle_abi.rs:207`, `src/wiggle_abi.rs:249`, `src/execute.rs:747`, and `src/execute.rs:758`.

## Why This Is A Real Bug
This is directly reachable from malformed guest input and converts an expected validation failure into a panic path. That changes behavior from recoverable API error handling to guest-terminating trap semantics, enabling denial of service for the invocation and bypassing the existing `Error` to status translation used elsewhere.

## Fix Requirement
Replace all unchecked KV store handle unwraps with checked lookups and return the existing handle-validation error on `None`, consistent with other checked handle paths such as `src/wiggle_abi/acl.rs:34`.

## Patch Rationale
The patch should preserve existing success-path behavior while making invalid handles fail closed through normal error returns. Applying the same validation to both the WITX ABI and component-model KV surface removes the panic primitive across both externally reachable interfaces.

## Residual Risk
None

## Patch
Implemented in `010-invalid-store-handle-can-panic-hostcall.patch`.