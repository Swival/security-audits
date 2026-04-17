# Relocation range end can wrap on 32-bit targets

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/readers/core/reloc.rs:241`

## Summary
`RelocationEntry::relocation_range()` derived a `Range<usize>` from untrusted relocation offsets using `self.offset as usize` and `start + self.ty.extent()`. On 32-bit targets, large parsed offsets can overflow the end computation, causing a debug-build panic or release-build wraparound instead of rejection.

## Provenance
- Verified from supplied reproduction and patch context
- Scanner: https://swival.dev

## Preconditions
- 32-bit `usize` target
- Parsed relocation entry with attacker-controlled `offset` near `u32::MAX`
- Relocation type extent of `4`, `5`, `8`, or `10`

## Proof
- `RelocationEntry::offset` is populated from untrusted input via `read_var_u32()`.
- `relocation_range()` converts that value with `self.offset as usize`.
- The previous end calculation used unchecked addition: `start + self.ty.extent()`.
- On 32-bit targets, values such as `offset = 0xffff_fffc` with extent `4`, or `offset = 0xffff_fff6` with extent `10`, overflow `usize`.
- Reproduction confirmed target-specific behavior for `i686-unknown-linux-gnu`: checked builds panic on overflow; optimized builds emit plain addition and wrap.
- Reachability is practical: `src/readers/core/custom.rs:92` recognizes `reloc.*` custom sections, `RelocSectionReader::new` parses them, and iteration exposes attacker-controlled `RelocationEntry` values to callers of the public helper.

## Why This Is A Real Bug
The helper promises a relocation byte range but could instead produce an invalid wrapped range or panic for malformed yet parseable input on supported 32-bit targets. Because the offset originates from attacker-controlled wasm relocation data and no overflow check existed at the range boundary computation, the API violated its validation contract and returned nonsensical results under realistic conditions.

## Fix Requirement
Use checked addition when computing the relocation range end and return an error if the end overflows `usize`.

## Patch Rationale
The patch in `001-relocation-range-end-can-wrap-on-32-bit-targets.patch` hardens `relocation_range()` by replacing unchecked end computation with `checked_add`, preserving existing behavior for valid inputs while rejecting overflowing ranges deterministically. This removes both the debug panic and release wraparound outcomes.

## Residual Risk
None

## Patch
- `001-relocation-range-end-can-wrap-on-32-bit-targets.patch` implements the required overflow check in `src/readers/core/reloc.rs` and converts the overflow case into an error return.