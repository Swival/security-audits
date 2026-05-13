# Indexing and slicing read beyond initialized `ScopeBuffer` length

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/internal/scopebuffer.d:162`
- `std/internal/scopebuffer.d` (`opSlice` bounds logic adjacent to `opIndex`)

## Summary
`ScopeBuffer` tracks the initialized extent in `used`, and `length`/`length=` maintain that invariant. However, `opIndex` and `opSlice` validate reads against `bufLen` instead of `used`. After shrinking the logical length, callers can still read bytes in the range `used <= index < bufLen`, disclosing stale or uninitialized buffer contents through public APIs.

## Provenance
- Verified from the supplied finding and local reproduction
- Source under review: `std/internal/scopebuffer.d`
- Scanner reference: https://swival.dev

## Preconditions
- Caller can invoke `opIndex` or `opSlice` with indices above the current logical length
- Backing storage exists up to `bufLen`
- `used < bufLen`, including after `length = 0` or any shrink via `length=`

## Proof
The implementation uses `used` as the initialized/logical length, but `opIndex` and `opSlice` compare caller-controlled `i`, `lower`, and `upper` against `bufLen`. This permits reads past initialized contents.

Reproduced behavior:
- Fresh `char[4] tmp = void` wrapped in `ScopeBuffer` with `length == 0`; `sb[0]` returned a nonzero byte
- After writing `ABCD` and shrinking to `length = 1`, reads still exposed stale bytes:
  - `sb[1]` returned `B`
  - `sb[2]` returned `C`
  - `sb[1 .. 4]` returned `BCD`

This demonstrates that public indexing and slicing APIs return data outside the logical contents when `used < bufLen`.

## Why This Is A Real Bug
The type’s own API establishes that `used` is the authoritative initialized extent. Allowing read access up to allocation capacity breaks that invariant and exposes bytes that are no longer logically part of the buffer, including never-initialized memory or stale prior contents after shrink. This is directly observable and reachable without undefined caller behavior beyond normal API use.

## Fix Requirement
`opIndex` and `opSlice` must validate read bounds against `used`, not `bufLen`, so reads cannot cross the initialized/logical end of the buffer.

## Patch Rationale
The patch changes read-side bounds enforcement to use `used`, aligning indexing and slicing with the existing `length` invariant. This is the narrowest fix: it preserves allocation capacity semantics while preventing disclosure of stale or uninitialized bytes through logical-length reads.

## Residual Risk
None

## Patch
Patched in `070-indexing-and-slicing-permit-reads-beyond-initialized-length.patch`.