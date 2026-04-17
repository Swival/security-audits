# Memory width decoded from reader state, not flags

## Classification
- Type: logic error
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/readers/core/memories.rs:31`

## Summary
`MemoryType::from_reader` selected the limit integer width from `reader.memory64()` instead of the just-parsed `memory64` flag. If reader feature state and encoded flags diverged, the parser decoded `initial` and `maximum` with the wrong varint width, yielding malformed `MemoryType` values or premature parse failures.

## Provenance
- Verified from the supplied reproducer and patched in `002-memory-width-decoded-from-reader-state-not-flags.patch`
- Scanner provenance: https://swival.dev

## Preconditions
- `BinaryReader` memory64 feature state differs from the parsed memory entry's `memory64` flag

## Proof
- In `src/readers/core/memories.rs:31`, width selection for memory limits was based on `reader.memory64()`, not the parsed flags byte.
- Reproduced case 1: a memory entry with `flags = 0x00` and `initial = 0x80 0x80 0x80 0x80 0x10` was accepted as `MemoryType { memory64: false, initial: 4294967296, ... }`.
- That decoded value is impossible for a valid 32-bit memory and only occurs because `read_var_u64()` was used where `read_var_u32()` should have been used.
- Reproduced case 2: with memory64 parsing disabled, an entry with `flags = 0x04` was decoded with `read_var_u32()` and failed with `invalid var_u32: integer too large`, instead of being decoded according to its own flag and later rejected by validation/feature gating.

## Why This Is A Real Bug
The memory flags byte is the authoritative source for whether a specific memory uses 32-bit or 64-bit limits. Using ambient reader state instead changes parser behavior based on configuration rather than on-wire contents. This produces observable mis-decoding through direct parsing APIs: invalid 32-bit memories can be surfaced as parsed values, and validly encoded 64-bit limits can fail in the parser before intended validation paths run.

## Fix Requirement
Use the parsed `memory64` flag for all limit-width decisions when reading `initial` and optional `maximum`.

## Patch Rationale
The patch replaces the `reader.memory64()` branch condition with the parsed `memory64` flag in `src/readers/core/memories.rs`, aligning width selection with the current memory entry's flags. This is the minimal change that restores correct decoding semantics without altering later validation behavior.

## Residual Risk
None

## Patch
- Patched in `002-memory-width-decoded-from-reader-state-not-flags.patch`
- Change scope: `src/readers/core/memories.rs`
- Effect: `initial` and `maximum` are now decoded using the parsed `memory64` flag rather than reader-global state