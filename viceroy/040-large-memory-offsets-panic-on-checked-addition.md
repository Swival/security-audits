# Large memarg offset overflow panics during rewrite

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/shift_mem.rs:140`
- `src/shift_mem.rs:153`

## Summary
- Module adaptation rewrites load/store `MemArg.offset` values by adding a fixed `OFFSET`.
- For offsets greater than `u32::MAX - 131072`, `checked_add(OFFSET as u32)` returns `None`.
- The current code calls `unwrap()`, so attacker-controlled Wasm can crash adaptation instead of receiving a normal error.

## Provenance
- Verified by reproduction against the target codebase.
- Reproducer exercised `viceroy_lib::adapt::adapt_wat(...)` with a crafted module containing `i32.load offset=4294836224`.
- Scanner provenance: https://swival.dev

## Preconditions
- A supplied Wasm module contains a load or store instruction with `memarg.offset > 4294836223`.

## Proof
- `OFFSET` is `131072` in `src/shift_mem.rs:18`.
- During rewriting, load/store handling performs `offset.checked_add(OFFSET as u32).unwrap()` in `src/shift_mem.rs:140` and `src/shift_mem.rs:153`.
- With input offset `4294836224`, `checked_add(131072)` overflows `u32` and returns `None`.
- Reproduction used a minimal module in `tests/repro_shift_mem.rs`.
- Running `cargo test -p viceroy-lib --test repro_shift_mem large_memarg_offset_panics_during_adaptation -- --nocapture` triggered:
  ```text
  thread 'large_memarg_offset_panics_during_adaptation' panicked at src/shift_mem.rs:140:68: called Option::unwrap() on a None value
  ```

## Why This Is A Real Bug
- The panic is directly reachable from untrusted Wasm input during normal adaptation.
- This bypasses the function’s `Result`-based error handling and crashes processing.
- The impact is denial of service in the adaptation path.

## Fix Requirement
- Replace `unwrap()` on shifted memory offsets with fallible error propagation.
- Return a structured adaptation error when offset rewriting would overflow `u32`.

## Patch Rationale
- The bug is not the overflow detection itself; `checked_add` already detects it.
- The flaw is converting that detected overflow into a panic with `unwrap()`.
- Propagating an error preserves existing control flow, prevents process abort, and keeps malicious inputs in the ordinary failure path.

## Residual Risk
- None

## Patch
- `040-large-memory-offsets-panic-on-checked-addition.patch`
- Patch intent:
  ```diff
  - memarg.offset = memarg.offset.checked_add(OFFSET as u32).unwrap();
  + memarg.offset = memarg
  +     .offset
  +     .checked_add(OFFSET as u32)
  +     .context("memory offset overflow while shifting load/store memarg")?;
  ```
