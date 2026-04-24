# Oversized shielding backend persists after length error

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/component/shielding.rs:31`
- `src/wiggle_abi/shielding_impl.rs:109`
- `src/session.rs:646`
- `src/linking.rs:360`
- `src/wiggle_abi/backend_impl.rs:10`
- `src/wiggle_abi/req_impl.rs:832`

## Summary
The shielding backend creation path inserts a dynamically generated backend into session state before verifying that the caller-provided output buffer can hold the generated backend name. If the later length check fails, the call returns `BufferLengthError` but the backend remains registered. This breaks all-or-nothing semantics for a failed shield creation and leaves a usable backend behind after an error.

## Provenance
- Verified from reproduced behavior and source inspection
- Scanner origin: https://swival.dev

## Preconditions
- Valid URI input
- `max_len` smaller than the generated shield backend name length

## Proof
- `backend_for_shield` derives a deterministic `new_name` from the attacker-controlled URI, then calls `session.add_backend(&new_name, new_backend)` before checking `target_len > max_len` in `src/wiggle_abi/shielding_impl.rs:109`.
- `Session::add_backend` immediately inserts into `self.dynamic_backends` with no rollback path in `src/session.rs:646`.
- The shielding hostcall is exposed to guests through the legacy ABI linker in `src/linking.rs:360`.
- After `BufferLengthError` is returned, later backend resolution still finds the persisted backend via `session.backend(...)` in `src/session.rs:625`, used by backend and request APIs in `src/wiggle_abi/backend_impl.rs:10` and `src/wiggle_abi/req_impl.rs:832`.
- Because the generated backend name is deterministic from the URI, the guest can predict it without receiving the copied-out buffer, intentionally trigger the error with a short buffer, and still use the persisted backend afterward.

## Why This Is A Real Bug
The failure path mutates durable session state even though the API reports failure. That is observable, reachable from guest code, and exploitable to create and use a backend that should not exist after an errored call. The bug is not theoretical because the backend remains resolvable through normal backend and request APIs.

## Fix Requirement
Validate `new_name.len()` against `max_len` before calling `session.add_backend`, so no session mutation occurs on the error path.

## Patch Rationale
The patch moves the output-length validation ahead of backend registration in the shielding implementation, preserving atomic behavior: either the call succeeds and the backend is added, or it fails with `BufferLengthError` and leaves no residual state. This directly matches the documented failure mode and removes the need for rollback logic.

## Residual Risk
None

## Patch
- Patched in `029-oversized-shielding-backend-persists-after-length-error.patch`
- The change ensures the max-length check executes before `session.add_backend(...)`, preventing backend persistence on the failing path.