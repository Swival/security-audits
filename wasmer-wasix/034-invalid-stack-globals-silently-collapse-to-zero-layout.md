# Invalid stack globals collapse stack base to zero

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/state/func_env.rs:207`
- `lib/wasix/src/state/func_env.rs:244`
- `lib/wasix/src/syscalls/mod.rs:1139`
- `lib/wasix/src/syscalls/mod.rs:1301`
- `lib/wasix/src/syscalls/wasix/stack_checkpoint.rs:87`

## Summary
`initialize_handles_and_layout` accepted `__stack_high` only as `I32`/`I64`, but treated non-integer `__stack_low` and fallback `__data_end` globals as `0`. For any positive `stack_upper`, the later ordering check still passed, so the runtime committed a stack layout with `stack_lower = 0`. Asyncify and stack-checkpoint paths then trusted that layout and used address `0` as stack scratch/storage instead of failing module initialization.

## Provenance
- Verified from the provided reproducer and code-path analysis in `lib/wasix/src/state/func_env.rs`
- Swival Security Scanner: https://swival.dev

## Preconditions
- Module exports `__stack_high`
- Exported `__stack_low` or fallback `__data_end` exists but is not an `I32`/`I64` global
- Instance initialization reaches `initialize_handles_and_layout`
- Asyncify or stack-checkpoint logic later consumes the committed layout

## Proof
- In `lib/wasix/src/state/func_env.rs:207`, exported globals are loaded into `initialize_handles_and_layout`
- When layout updates are enabled, `__stack_high` is validated as integer and nonzero
- `__stack_low.get(store)` and fallback `__data_end.get(store)` mapped any non-`I32`/`I64` value to `0`
- The subsequent `stack_lower >= stack_upper` check at `lib/wasix/src/state/func_env.rs:244` did not reject `stack_lower = 0` when `stack_upper > 0`
- The bad layout was committed and later consumed by:
  - `lib/wasix/src/syscalls/mod.rs:1139` during `unwind`
  - `lib/wasix/src/syscalls/mod.rs:1301` during `rewind`
  - `lib/wasix/src/syscalls/wasix/stack_checkpoint.rs:87` during stack range handling
- Result: asyncify scratch metadata and stack operations could target address `0` instead of the reserved stack interval

## Why This Is A Real Bug
This is reachable in normal instance initialization from exported module globals, not a hypothetical internal misuse. The runtime already treats `__stack_high` type mismatches as fatal, which shows these globals are part of a trusted ABI contract. Silently coercing invalid `__stack_low`/`__data_end` to `0` breaks that contract, produces a materially different stack layout, and propagates into later memory writes and range calculations. The correct behavior is initialization failure, not layout repair by zeroing.

## Fix Requirement
Reject non-`I32`/`I64` `__stack_low` and `__data_end` globals with `ExportError` during layout initialization instead of defaulting them to `0`.

## Patch Rationale
The patch makes lower-bound stack globals follow the same validation model already used for `__stack_high`: only integer globals are accepted. This removes silent coercion, preserves ABI consistency, and fails closed before any corrupted layout can be stored or consumed by asyncify or stack-checkpoint code.

## Residual Risk
None

## Patch
`034-invalid-stack-globals-silently-collapse-to-zero-layout.patch` rejects non-integer `__stack_low` and fallback `__data_end` globals in `lib/wasix/src/state/func_env.rs`, returning `ExportError` instead of committing `stack_lower = 0`.