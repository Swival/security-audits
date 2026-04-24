# Supported wasm instructions hit todo panic

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/shift_mem.rs:161`

## Summary
- Valid user-controlled Wasm passed into memory shifting can reach `shift_func`, where supported memory instructions `Instr::AtomicNotify`, `Instr::AtomicWait`, `Instr::AtomicRmw`, `Instr::Cmpxchg`, and `Instr::LoadSimd` previously executed `todo!()`.
- `todo!()` is an unconditional panic, so a module containing one of these instructions aborts rewriting instead of returning an error, causing a reliable denial of service on reachable input.

## Provenance
- Reproduced from the supplied finding and validated against the implementation in `src/shift_mem.rs`.
- Reference: Swival Security Scanner at https://swival.dev

## Preconditions
- A valid Wasm module reaches the memory-shifting path.
- The module contains at least one of `Instr::AtomicNotify`, `Instr::AtomicWait`, `Instr::AtomicRmw`, `Instr::Cmpxchg`, or `Instr::LoadSimd`.

## Proof
- User-supplied bytes flow into the adaptation pipeline and, when memory shifting is required, into `shift_main_module`, which parses and rewrites local functions.
- During rewriting, `shift_func` matches instructions and previously routed the listed atomic and SIMD memory operations to `todo!()` in `src/shift_mem.rs:161`.
- I verified reachability with a valid module containing `v128.load8_splat`:
```wat
(module
  (memory 1)
  (func (export "_start")
    i32.const 0
    v128.load8_splat
    drop))
```
- Compiling that module and passing it to `viceroy_lib::adapt::adapt_bytes` triggered:
```text
thread 'main' panicked at src/shift_mem.rs:166:39: not yet implemented
```
- This is a deterministic crash on attacker-controlled input, establishing denial of service.

## Why This Is A Real Bug
- The crashing inputs are valid Wasm, not malformed edge cases.
- The affected instructions are explicitly supported by the parser and are reachable through normal function rewriting.
- Panic-based termination bypasses normal error handling and aborts processing for the entire request or process.
- Although some modules may avoid the shift path, any module that does enter it with one of these instructions reliably crashes, so exploitability is real and input-driven.

## Fix Requirement
- Eliminate the `todo!()` panic path for these instructions.
- Either rewrite these instructions like other memory operations by applying the memory offset shift, or return a structured error indicating unsupported rewriting.
- The fix must preserve non-panicking behavior for valid attacker-controlled inputs.

## Patch Rationale
- The patch in `041-supported-wasm-instructions-hit-todo-panic.patch` replaces the panic path with explicit handling so these supported instructions no longer abort the process during rewriting.
- This satisfies the core requirement by converting a crash-on-input condition into safe instruction processing within the existing rewrite flow.

## Residual Risk
- None

## Patch
- `041-supported-wasm-instructions-hit-todo-panic.patch`