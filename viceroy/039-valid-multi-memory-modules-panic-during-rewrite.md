# Valid multi-memory modules panic during rewrite

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/shift_mem.rs:192`

## Summary
`shift_main_module` accepts valid WebAssembly binaries, then unconditionally asserts that any module with memories has exactly one memory. Valid multi-memory modules therefore panic during rewrite instead of returning a normal error, making accepted inputs unrewriteable and turning a bad internal assumption into a reachable crash.

## Provenance
- Verified from the provided reproducer and patch context
- Reference: https://swival.dev

## Preconditions
- The input WebAssembly module defines more than one memory
- The module reaches the `shift_main_module` rewrite path

## Proof
`adapt_bytes` routes qualifying modules into `crate::shift_mem::shift_main_module(bytes)` after parsing succeeds. Inside `shift_main_module`, `Module::from_buffer(bytes)?` accepts the valid multi-memory module, then execution reaches the non-empty memory branch and hits `assert!(module.memories.len() == 1);` at `src/shift_mem.rs:192`. A harness using `std::panic::catch_unwind(|| viceroy_lib::adapt::adapt_wat(wat))` captures the panic from that location, confirming the function aborts instead of returning `Result`.

## Why This Is A Real Bug
The crash is reachable with a valid WebAssembly feature combination, not malformed input. Because the function already models failure with `Result`, panicking here violates the API contract and prevents callers from handling the condition safely. This is a correctness and availability issue for any consumer that attempts to rewrite valid multi-memory modules.

## Fix Requirement
Replace the assertion with explicit handling for multiple memories or return a descriptive error when multi-memory input is unsupported.

## Patch Rationale
The patch removes the panic path by replacing the hard assertion with explicit validation and structured failure. That preserves process stability, keeps behavior consistent with the function’s `Result`-based interface, and makes unsupported multi-memory modules fail predictably with a clear error instead of aborting execution.

## Residual Risk
None

## Patch
- `039-valid-multi-memory-modules-panic-during-rewrite.patch`