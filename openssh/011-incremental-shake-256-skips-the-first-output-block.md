# Incremental SHAKE-256 skips the first output block

## Classification

Cryptographic flaw, high severity.

Confidence: certain.

## Affected Locations

`libcrux_mlkem768_sha3.h:1856`

`libcrux_mlkem768_sha3.h:5037`

`libcrux_mlkem768_sha3.h:5043`

`libcrux_mlkem768_sha3.h:5049`

## Summary

The incremental SHAKE-256 XOF squeeze path emits an incorrect stream when the first squeeze request is longer than one SHAKE-256 rate block, 136 bytes. In that case, the implementation permutes the finalized Keccak state before writing the first full output block, so output begins at block 1 instead of block 0.

The patch makes the long-output branch squeeze the current finalized state first, then permute before subsequent blocks.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the supplied source and runtime comparison evidence.

## Preconditions

- A `Shake256Xof` state is initialized.
- The state is finalized.
- No prior squeeze has occurred.
- The first squeeze request has `out_len > 136`.

## Proof

The incremental SHAKE-256 state is initialized with `sponge = false` in `libcrux_mlkem768_sha3.h:5004`. Finalization at `libcrux_mlkem768_sha3.h:4962` does not change that flag.

In `libcrux_sha3_generic_keccak_xof_squeeze_85_c7`, the top-level pre-squeeze permutation is conditional:

```c
if (self->sponge) {
  libcrux_sha3_generic_keccak_keccakf1600_80_04(&self->inner);
}
```

For a first squeeze, `self->sponge` is still false, so this permutation is skipped.

The short-output branch, `out_len <= 136`, correctly writes the current finalized state directly at `libcrux_mlkem768_sha3.h:5043`. The long-output branch, `out_len > 136`, instead entered a loop beginning at block index 0 and called `libcrux_sha3_generic_keccak_keccakf1600_80_04` before writing output at `libcrux_mlkem768_sha3.h:5049`. That makes the first caller-visible full block the second SHAKE-256 block.

Runtime reproduction for `SHAKE256("abc")` with a 272-byte first incremental squeeze confirmed the defect:

- Observed first bytes: `cf0ea610eeff1a588290a53000faa799`
- These match one-shot SHAKE256 bytes `[136..151]`
- Correct first bytes are: `483366601360a8771c6863080cc4114d`

## Why This Is A Real Bug

SHAKE-256 is an extendable-output function with a specified byte stream. Incremental and one-shot APIs must produce the same prefix for the same input and output length.

The implementation produces a deterministic stream shifted by one full 136-byte rate block only for the first incremental squeeze longer than 136 bytes. This breaks SHAKE-256 correctness and can corrupt any protocol or construction that derives keys, randomness, masks, or sampling bytes from the incremental SHAKE-256 API.

## Fix Requirement

For the first long squeeze after finalization, the implementation must:

1. Squeeze the current finalized Keccak state into output block 0.
2. Apply `keccakf1600` before each subsequent full block.
3. Apply `keccakf1600` before any remaining partial block after the full blocks.
4. Preserve existing behavior for later squeezes where `self->sponge` is already true.

## Patch Rationale

The patch changes only the long-output branch for SHAKE-256 incremental squeeze.

Before the patch, the loop started at `i = 0` and permuted before writing block 0. After the patch, the branch writes block 0 directly from the current finalized state, then starts the permutation/write loop at `i = 1`.

This aligns the long-output branch with the already-correct short-output branch and with the one-shot SHAKE-256 implementation pattern, where the first block is squeezed before the first post-finalization permutation.

## Residual Risk

None

## Patch

```diff
diff --git a/libcrux_mlkem768_sha3.h b/libcrux_mlkem768_sha3.h
index 1e3dc45..471dcaf 100644
--- a/libcrux_mlkem768_sha3.h
+++ b/libcrux_mlkem768_sha3.h
@@ -5044,7 +5044,9 @@ static KRML_MUSTINLINE void libcrux_sha3_generic_keccak_xof_squeeze_85_c7(
                                                out_len);
     } else {
       size_t blocks = out_len / (size_t)136U;
-      for (size_t i = (size_t)0U; i < blocks; i++) {
+      libcrux_sha3_simd_portable_squeeze_13_5b(&self->inner, out, (size_t)0U,
+                                               (size_t)136U);
+      for (size_t i = (size_t)1U; i < blocks; i++) {
         size_t i0 = i;
         libcrux_sha3_generic_keccak_keccakf1600_80_04(&self->inner);
         libcrux_sha3_simd_portable_squeeze_13_5b(
```