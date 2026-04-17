# Split input overruns block buffers for oversized lengths

## Classification
- Type: vulnerability
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/quiclb-impl.h:68`
- `lib/quiclb-impl.h:132`
- `lib/quiclb-impl.h:135`
- `include/picotls.h:2075`
- `lib/openssl.c:1451`
- `lib/openssl.c:1457`
- `lib/openssl.c:1467`
- `lib/fusion.c:2198`
- `lib/fusion.c:2204`
- `lib/fusion.c:2214`

## Summary
`picotls_quiclb_split_input` writes `(len + 1) / 2` bytes into each `union picotls_quiclb_block`, which is only `PTLS_AES_BLOCK_SIZE` bytes wide. For `len > 32`, each copy loop overruns the 16-byte block buffers. In release builds, the only length guard is an `assert`, so oversized caller-controlled lengths can reach `picotls_quiclb_transform` through the exported QUICLB cipher path and trigger memory corruption.

## Provenance
- Verified from the supplied reproducer trace and source review in the affected files.
- Scanner source: https://swival.dev

## Preconditions
- Caller passes `len > 32` into `picotls_quiclb_split_input`.
- Build disables assertions, or caller otherwise reaches the transform path without a runtime length check.
- Application uses the exported QUICLB cipher interface so untrusted or unchecked lengths reach `ptls_cipher_encrypt`.

## Proof
- `picotls_quiclb_split_input` copies alternating source bytes into `l->bytes[i / 2]` and `r->bytes[i / 2]` for all `i < len`, with no capacity bound before the writes at `lib/quiclb-impl.h:68`.
- Each destination is `union picotls_quiclb_block`, backed by `PTLS_AES_BLOCK_SIZE` bytes, i.e. 16 bytes.
- When `len > 32`, `(len + 1) / 2 > 16`, so both loops write beyond the end of `l->bytes` and `r->bytes` before later zero-fill logic runs.
- `picotls_quiclb_transform` accepts `len` and forwards it into the split logic; its intended range check is only `assert(PTLS_QUICLB_MIN_BLOCK_SIZE <= len && len <= PTLS_QUICLB_MAX_BLOCK_SIZE)` at `lib/quiclb-impl.h:132`.
- In release builds, that assertion is removed. The call chain remains reachable because `ptls_cipher_encrypt` forwards `len` directly to the cipher `do_transform` callback at `include/picotls.h:2075`, and the OpenSSL/Fusion QUICLB handlers pass that value through unchanged at `lib/openssl.c:1451`, `lib/openssl.c:1457`, `lib/openssl.c:1467`, `lib/fusion.c:2198`, `lib/fusion.c:2204`, and `lib/fusion.c:2214`.

## Why This Is A Real Bug
This is a concrete out-of-bounds write on stack-backed fixed-size block buffers. It is not merely an assertion misuse: in optimized production builds, the asserted invariant disappears, yet the exported API still accepts and forwards arbitrary `len`. That makes the overwrite reachable by a caller that invokes the QUICLB cipher directly, with memory corruption occurring before any later bounds-sensitive logic can contain it.

## Fix Requirement
Add a runtime length check in the QUICLB transform path that rejects oversized lengths before any table lookup or split-buffer write occurs. The guard must not rely on `assert` alone.

## Patch Rationale
The patch enforces the QUICLB length contract at runtime before `masks[...]` indexing and before `picotls_quiclb_split_input` runs. Rejecting invalid `len` values is preferable to silently truncating copy loops because it preserves the algorithm's defined input domain, prevents both the mask-table overread and the split-buffer overflow, and keeps behavior explicit for callers in release builds.

## Residual Risk
None

## Patch
- Patch file: `014-split-input-overruns-block-buffers-for-oversized-lengths.patch`
- Effect: adds a non-assert runtime guard so invalid QUICLB input lengths are rejected before unsafe indexing and block-buffer writes occur in `lib/quiclb-impl.h`.