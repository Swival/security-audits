# Invalid store handle panics host insert paths

## Classification
- Type: error-handling bug
- Severity: high
- Confidence: certain

## Affected Locations
- `src/wiggle_abi/obj_store_impl.rs:83`
- `src/wiggle_abi/obj_store_impl.rs:99`
- Patch: `018-invalid-store-handle-panics-host-insert-paths.patch`

## Summary
Guest-controlled `ObjectStoreHandle` values reached host insert paths and were converted with `self.get_kv_store_key(store.into()).unwrap().clone()`. When the handle was unmapped, the lookup returned `None` and the host panicked instead of returning a normal invalid-handle error.

## Provenance
- Verified by reproduction against the local codebase
- Reported from Swival Security Scanner: https://swival.dev

## Preconditions
- A guest can invoke the object store insert hostcalls
- The guest supplies an invalid or unmapped `ObjectStoreHandle`

## Proof
- `insert` and `insert_async` accepted guest-provided store handles and performed unchecked lookup/unwrap in `src/wiggle_abi/obj_store_impl.rs:83` and `src/wiggle_abi/obj_store_impl.rs:99`
- `get_kv_store_key` returned `None` for unmapped handles, making the subsequent `unwrap()` panic
- Runtime reproduction used a minimal WAT guest that called `fastly_object_store#insert` with fabricated store handle `123`
- Running `cargo run -p viceroy -- run test-fixtures/invalid_obj_store_insert.wat` crashed with `called 'Option::unwrap()' on a 'None' value`, proving direct guest-triggerable reachability

## Why This Is A Real Bug
This is not a theoretical panic path. The invalid handle is attacker-controlled guest input, the hostcall reaches the unwrap without prior validation, and the reproduced execution crashes on demand. The intended behavior for bad handles in this ABI is to return a handled error such as `Badf`, so the panic is a reliability and isolation failure in a host-facing boundary.

## Fix Requirement
Replace the unchecked `unwrap()`-based store-key conversion in insert paths with checked handling that returns the existing invalid-handle error instead of panicking.

## Patch Rationale
The patch updates the insert paths to validate the incoming store handle before dereferencing it, mapping lookup failure into the established invalid-handle error path. This preserves expected ABI behavior, removes the panic primitive, and keeps error handling consistent with other handle-validation logic.

## Residual Risk
None

## Patch
- File: `018-invalid-store-handle-panics-host-insert-paths.patch`
- Change: replace unchecked store-handle unwrap in object-store insert paths with checked conversion returning the existing invalid-handle error
- Result: invalid guest store handles no longer crash the host insert path and instead fail gracefully with a normal error