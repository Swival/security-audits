# Load failure panics the process

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/wasix/closure_prepare.rs:378`
- `lib/wasix/src/syscalls/wasix/closure_prepare.rs:383`
- `lib/wasix/src/syscalls/wasix/closure_prepare.rs:387`

## Summary
`closure_prepare` builds and dynamically loads an in-memory module from syscall-controlled inputs. When `linker.load_module(wasm_loader, &mut ctx)` returns an error, the code calls `panic!` instead of converting the failure into a normal syscall error, making a handled loader failure abort the process.

## Provenance
- Verified from the provided reproducer and source inspection
- Scanner origin: https://swival.dev

## Preconditions
- `closure_prepare` runs with dynamic module loading enabled

## Proof
`closure_prepare` constructs a side module using syscall parameters, including table writes derived from the caller-provided `closure` index at `lib/wasix/src/syscalls/wasix/closure_prepare.rs:219` and `lib/wasix/src/syscalls/wasix/closure_prepare.rs:225`.

Newly loaded side modules always execute `__wasm_call_ctors` during load at `lib/wasix/src/state/linker.rs:1752` and `lib/wasix/src/state/linker.rs:1754`.

If the supplied `closure` index is invalid or out of bounds, the generated `table_set` traps during ctor execution. The loader translates that trap into `LinkError::InitFunctionFailed` at `lib/wasix/src/state/linker.rs:4265` and `lib/wasix/src/state/linker.rs:4269`, causing `linker.load_module(...)` to return `Err`.

That error reaches `closure_prepare`, which panics on the error path at `lib/wasix/src/syscalls/wasix/closure_prepare.rs:383` and `lib/wasix/src/syscalls/wasix/closure_prepare.rs:387` rather than returning `Errno` or `WasiError`. This makes the crash directly reachable from the syscall surface.

## Why This Is A Real Bug
The failing condition is not hypothetical: module load failure is an expected recoverable outcome already represented as a `Result` by `load_module`. Panicking discards that error boundary and terminates the process from a syscall-triggerable input path. Because the invalid module state is derived from syscall parameters, an untrusted caller can reliably convert a normal loader error into process abort.

## Fix Requirement
Replace the panic on `load_module` failure with normal syscall error propagation, mapping loader failures to an appropriate `WasiError` or `Errno` such as `Errno::Io` or `Errno::Inval`.

## Patch Rationale
The patch in `042-load-failure-panics-the-process.patch` removes the panic-based handling in `closure_prepare` and converts `load_module` failures into a returned syscall error. This preserves process integrity, keeps behavior aligned with Rust `Result` semantics already used by the loader, and ensures malformed or trap-producing dynamically built modules fail closed without aborting the host.

## Residual Risk
None

## Patch
`042-load-failure-panics-the-process.patch`