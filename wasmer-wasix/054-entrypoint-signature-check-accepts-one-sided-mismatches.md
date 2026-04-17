# Entrypoint signature check accepts one-sided mismatches

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/wasix/context_create.rs:31`

## Summary
`context_create` validates a caller-selected entrypoint via `lookup_typechecked_entrypoint`, but the predicate rejects only when both parameter and result lists are non-empty. This admits one-sided mismatches against the required `() -> ()` signature: functions with parameters only or results only are accepted. The syscall later invokes the entrypoint with zero arguments and ignores returned values, causing deferred failure instead of early rejection.

## Provenance
- Verified from the provided reproducer and source inspection
- Scanner source: https://swival.dev

## Preconditions
- Attacker controls indirect-table entrypoint selection

## Proof
- `context_create` accepts a caller-supplied `entrypoint` and resolves it through `lookup_typechecked_entrypoint` at `lib/wasix/src/syscalls/wasix/context_create.rs:31`.
- The existing signature gate rejects only when both `params` and `results` are non-empty, so params-only and results-only functions pass validation.
- The accepted function is later invoked as `entrypoint.call_async(&async_store, vec![])`, always with zero arguments.
- For params-only mismatches, the bad entrypoint survives initial validation and fails only at call time due to Wasmer arity enforcement.
- For results-only mismatches, the zero-arg call succeeds, outputs are discarded, and normal return is converted into `ContextEntrypointReturned` during context switching, surfacing as a context-start abort rather than successful execution.

## Why This Is A Real Bug
The bug is a real validation failure because the syscall promises an empty-signature entrypoint but accepts functions that do not satisfy that contract. The engine later prevents unsafe execution, so this is not type confusion, but the guard still fails its intended purpose: malformed entrypoints are admitted and rejected only after context creation has progressed. That creates observable late failure behavior and violates the API's signature-checking requirement.

## Fix Requirement
Reject any entrypoint whose signature is not exactly `() -> ()`. In practice, fail when either parameters or results are non-empty, or compare for exact empty-signature equality.

## Patch Rationale
The patch in `054-entrypoint-signature-check-accepts-one-sided-mismatches.patch` tightens the signature check to reject one-sided mismatches at validation time. This moves failure to the correct boundary, aligns behavior with the documented empty entrypoint contract, and prevents deferred context-start aborts caused by invalid table selections.

## Residual Risk
None

## Patch
```patch
*** Begin Patch
*** Update File: lib/wasix/src/syscalls/wasix/context_create.rs
@@
-    if !ty.params().is_empty() && !ty.results().is_empty() {
+    if !ty.params().is_empty() || !ty.results().is_empty() {
         return Err(Errno::Inval);
     }
*** End Patch
```