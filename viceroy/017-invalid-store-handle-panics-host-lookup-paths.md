# Invalid store handle panics host lookup paths

## Classification
- Type: error-handling bug
- Severity: high
- Confidence: certain

## Affected Locations
- `src/wiggle_abi/obj_store_impl.rs:34`
- `src/linking.rs:357`
- `src/execute.rs:587`
- `src/execute.rs:597`
- `wasm_abi/compute-at-edge-abi/compute-at-edge.witx:1095`
- `wasm_abi/compute-at-edge-abi/compute-at-edge.witx:1102`
- `wasm_abi/compute-at-edge-abi/compute-at-edge.witx:1115`
- `wasm_abi/compute-at-edge-abi/compute-at-edge.witx:1122`
- `wasm_abi/compute-at-edge-abi/compute-at-edge.witx:1135`

## Summary
Guest-callable object store host functions accepted an `ObjectStoreHandle` and immediately executed `self.get_kv_store_key(store.into()).unwrap()`. A forged or unopened handle therefore triggered a host panic instead of returning a normal ABI `Error`, breaking expected error isolation for guest input.

## Provenance
- Verified from the provided reproducer and source inspection
- Swival Security Scanner: https://swival.dev

## Preconditions
- Guest passes an unopened or forged `ObjectStoreHandle`

## Proof
- `lookup`, `lookup_async`, `insert`, `insert_async`, and `delete_async` consume a guest-provided store handle and called `self.get_kv_store_key(store.into()).unwrap()`.
- `get_kv_store_key(...)` returns `None` for an invalid handle; `unwrap()` therefore panics immediately.
- These functions are exposed as guest-reachable hostcalls through the object store ABI and linking layer at `src/linking.rs:357`, with corresponding ABI entries in `wasm_abi/compute-at-edge-abi/compute-at-edge.witx:1095`, `wasm_abi/compute-at-edge-abi/compute-at-edge.witx:1102`, `wasm_abi/compute-at-edge-abi/compute-at-edge.witx:1115`, `wasm_abi/compute-at-edge-abi/compute-at-edge.witx:1122`, and `wasm_abi/compute-at-edge-abi/compute-at-edge.witx:1135`.
- The panic is not normalized into an ABI error. Guest execution is awaited with `.await.expect("guest worker finished without panicking")` at `src/execute.rs:587` and `src/execute.rs:597`, so the panic propagates as a task/request failure rather than a returned Fastly error.

## Why This Is A Real Bug
The failing condition is fully guest-controlled and occurs on a normal hostcall path. The implementation promises fallible host operations returning `Result<_, Error>`, but an invalid handle bypassed that contract and terminated execution via panic. Even without proving whole-process termination in every embedding, panic-on-input is a concrete availability and isolation failure because invalid guest data causes request execution to abort instead of receiving a checked error.

## Fix Requirement
Replace each `unwrap()` on the resolved store key with checked handling that maps invalid `ObjectStoreHandle` values to the appropriate ABI `Error` return path.

## Patch Rationale
The patch removes panic-based handle resolution in `src/wiggle_abi/obj_store_impl.rs` and performs explicit validation before continuing with object store operations. Invalid handles now return a normal `Error`, preserving hostcall error semantics and preventing guest-controlled panics from escaping through the execution path.

## Residual Risk
None

## Patch
- `017-invalid-store-handle-panics-host-lookup-paths.patch`