# Split input overruns block buffers for oversized lengths

## Classification
- Type: vulnerability
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/quiclb-impl.h:68`
- `lib/quiclb-impl.h:132`
- `lib/quiclb-impl.h:135`

## Summary
`picotls_quiclb_split_input` writes `(len + 1) / 2` bytes into `l->bytes` and `r->bytes`, but each destination is a `union picotls_quiclb_block` backed by `PTLS_AES_BLOCK_SIZE` bytes. For `len > 32`, the split loops exceed the 16-byte block capacity and overrun both buffers. The reachable caller path keeps `len` unvalidated in release builds because the only guard is an `assert`.

## Provenance
- Verified from the supplied finding and reproducer against `lib/quiclb-impl.h` and the exported QUICLB cipher call path
- External scanner reference: https://swival.dev

## Preconditions
- Caller passes `len > 32` into `picotls_quiclb_split_input`
- Build is compiled with `NDEBUG` or otherwise lacks an active runtime length check
- Application exposes the QUICLB cipher path through `ptls_cipher_encrypt`

## Proof
- `picotls_quiclb_split_input` copies `(len + 1) / 2` bytes into each half-buffer starting at `lib/quiclb-impl.h:68`
- `union picotls_quiclb_block` stores only `PTLS_AES_BLOCK_SIZE` bytes, so any split count above 16 overruns the destination
- When `len > 32`, `(len + 1) / 2 > 16`, so both write loops overflow before later zero-fill logic can help
- `picotls_quiclb_transform` forwards its `len` into the split helper, and its intended bounds check at `lib/quiclb-impl.h:132` is only an `assert`
- In release builds, that assertion is removed, making oversized input practically reachable through the exported QUICLB handlers described in the reproducer

## Why This Is A Real Bug
This is a concrete memory-safety violation, not just a spec mismatch. The destination buffers are fixed-size AES blocks, while the function derives copy counts directly from attacker-controlled `len`. Once `len` exceeds 32, the writes necessarily cross object bounds. The bug is reachable through public encryption entrypoints because they forward `len` unchanged, and the only existing validation disappears in production-style builds.

## Fix Requirement
Enforce a runtime upper bound before any mask lookup or split write occurs. The fix must reject oversized `len` values independently of assertions so release builds cannot enter the unsafe path.

## Patch Rationale
The patch adds a real length guard in the QUICLB transform path before dependent operations execute. This blocks the oversized input that causes the split-buffer overwrite and also prevents subsequent out-of-range table access on the mask array. Placing the check in the shared transform path preserves normal behavior for valid inputs while protecting all callers.

## Residual Risk
None

## Patch
- Patch file: `014-split-input-overruns-block-buffers-for-oversized-lengths.patch`
- Patch effect: add a runtime `len` validation in `lib/quiclb-impl.h` so inputs outside the supported QUICLB range are rejected before mask indexing and block splitting occur