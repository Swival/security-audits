# BlockVec xorBytes has invalid element assignment and fixed-size return

## Classification
- Type: data integrity bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/crypto/aes/soft.zig:414`

## Summary
`BlockVec.xorBytes` in `lib/std/crypto/aes/soft.zig` is incorrectly declared to return `[32]u8` regardless of `blocks_count`, and its loop assigns the result of `Block.xorBytes` (`[16]u8`) into `out[i]` (`Block`). In practice, the element-type mismatch causes a compile-time failure before the fixed-size return can manifest. The public method is therefore unusable for callers on backends using `soft.zig`.

## Provenance
- Verified from the provided reproducer and source inspection in `lib/std/crypto/aes/soft.zig:414`
- Public API reachability confirmed via `lib/std/crypto/aes.zig:23`
- Scanner source: https://swival.dev

## Preconditions
- `BlockVec` is instantiated for any `blocks_count`
- A caller invokes `BlockVec.xorBytes(...)`
- The selected AES backend uses `lib/std/crypto/aes/soft.zig`

## Proof
- `BlockVec.xorBytes` writes `out[i] = in[i].xorBytes(...)`, but `out[i]` is `Block` while `Block.xorBytes` returns `[16]u8` from `lib/std/crypto/aes/soft.zig:34`
- A minimal reproduction matching this pattern fails with Zig type checking: `expected type 'Block', found '[16]u8'`
- The method also declares return type `[32]u8`, which only matches `blocks_count == 2`; this violates the generic byte-length contract for other instantiations
- `BlockVec` is publicly re-exported, so external callers can reach this method on `soft.zig` backends

## Why This Is A Real Bug
This is a real public API defect: the method cannot compile as written when used, making `BlockVec.xorBytes` unusable on affected backends. The fixed `[32]u8` return type independently encodes the wrong contract for generic `blocks_count`, so even after correcting the assignment, the method would still return the wrong shape unless patched.

## Fix Requirement
Change `BlockVec.xorBytes` to:
- return `[blocks_count * 16]u8`
- convert each XOR result back into `Block` before storing, or build bytes directly
- return `out.toBytes()` so the result size matches `blocks_count`

## Patch Rationale
The patch updates the method signature to the correct generic byte length and returns `out.toBytes()`. It also resolves the element assignment mismatch by ensuring the loop stores `Block` values, preserving the existing `BlockVec` internal representation while restoring a usable and correctly typed API.

## Residual Risk
None

## Patch
- Patch file: `087-blockvec-xorbytes-returns-fixed-32-byte-array.patch`