# BlockVec `orBlocks` uses wrong parameter type

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/crypto/aes/soft.zig:461`
- `lib/std/crypto/aes/armcrypto.zig:282`
- `lib/std/crypto/aes/aesni.zig:315`

## Summary
`BlockVec(...).orBlocks` is declared with a scalar `Block` parameter but implemented as if the argument were a vector `Self`, indexing `block_vec2.repr[i]` inside a loop over vector lanes. This makes the method internally inconsistent and unusable as a correct block-vector OR operation.

## Provenance
- Verified from source and reproduced by inspection against the checked-in implementation
- Swival Security Scanner: https://swival.dev

## Preconditions
- Any call to `BlockVec(...).orBlocks`

## Proof
In `lib/std/crypto/aes/soft.zig:461`, `orBlocks` is declared as taking `block_vec2: Block`, then loops over vector lanes and reads `block_vec2.repr[i]`. That body requires `block_vec2` to be `Self`, not `Block`.

`Block.repr` is a fixed `[4]u32`, while `Self.repr` is `[native_words]Block`. Therefore:
- for any `i`, `block_vec2.repr[i]` has type `u32`, but `Block.orBlocks` expects a `Block`
- for `i >= 4`, the code additionally indexes past the bounds implied by `Block.repr`

The same broken signature/body pattern appears in `lib/std/crypto/aes/armcrypto.zig:282` and `lib/std/crypto/aes/aesni.zig:315`, confirming this is a copy-pasted API bug.

Repository search found no in-tree call sites for these methods, so the issue is latent. If invoked, the observable outcome is compilation failure, not correct execution.

## Why This Is A Real Bug
This is not stylistic or theoretical: the function signature and function body cannot both be correct. The implementation attempts a lane-wise vector OR, but the declared parameter type only provides a single block. That violates the method's own data-shape invariant and prevents valid use of the API.

## Fix Requirement
Change the `orBlocks` parameter type from `Block` to `Self` in each affected `BlockVec` implementation so the body operates on a same-shaped vector argument, matching the neighboring `xorBlocks` and `andBlocks` APIs.

## Patch Rationale
The patch makes the signature agree with the existing loop body and with adjacent vector combinator methods. This is the minimal, source-grounded correction and preserves the intended lane-wise semantics.

## Residual Risk
None

## Patch
Patched in `088-blockvec-orblocks-reads-non-existent-repr-field.patch`.