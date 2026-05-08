# SHAKE256 XOF Skips First Output Block

## Classification

Cryptographic flaw, high severity. Confidence: certain.

## Affected Locations

- `usr.bin/ssh/libcrux_mlkem768_sha3.h:5049` (SHAKE256, rate=136)
- `usr.bin/ssh/libcrux_mlkem768_sha3.h:5347` (SHAKE128, rate=168)

## Summary

The portable incremental SHAKE256 and SHAKE128 XOF multi-block squeeze paths permute the finalized Keccak state before emitting block 0. For requests larger than the respective rate (136 bytes for SHAKE256, 168 bytes for SHAKE128), the first returned block is therefore output block 1, not block 0. This makes incremental XOF output nonstandard for large requests.

Note: these incremental squeeze functions are currently unreachable dead code in the ML-KEM implementation used by OpenSSH, which only uses one-shot operations. However, they ship in the header and would produce incorrect output if called.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- A portable incremental SHAKE256 XOF state has been finalized through `libcrux_sha3_portable_incremental_absorb_final_42`.
- A caller requests more than 136 bytes through `libcrux_sha3_portable_incremental_squeeze_42`.

## Proof

The affected call path is:

- `libcrux_sha3_portable_incremental_squeeze_42`
- `libcrux_sha3_generic_keccak_xof_squeeze_85_c7`

In `libcrux_sha3_generic_keccak_xof_squeeze_85_c7`:

- A newly finalized XOF state has `self->sponge == false`, so the entry permutation guarded by `if (self->sponge)` does not run.
- For `out_len <= 136`, the function squeezes directly from the finalized state, which is correct.
- For `out_len > 136`, the multi-block branch computes `blocks = out_len / 136` and loops from `i = 0`.
- Before the patch, the loop called `libcrux_sha3_generic_keccak_keccakf1600_80_04(&self->inner)` before every block, including `i = 0`.
- The first emitted block at output offset 0 was therefore produced after an extra permutation.

A local reproducer using input `abc` confirmed this behavior: a 272-byte incremental squeeze did not match one-shot SHAKE256 output from offset 0, but exactly matched the one-shot SHAKE256 stream starting at offset 136.

## Why This Is A Real Bug

SHAKE256 XOF output is defined as the byte stream squeezed from the finalized Keccak state, with a permutation only between output blocks. The finalized state already contains the first output block. Permuting before emitting block 0 skips that block and shifts the stream by 136 bytes for multi-block incremental requests.

This is observable, deterministic, and incompatible with standard SHAKE256. Any caller relying on the portable incremental SHAKE256 XOF for more than one rate block receives incorrect cryptographic material.

## Fix Requirement

The implementation must emit block 0 directly from the finalized state. It must permute only before subsequent full blocks and before any trailing partial block after the last emitted full block.

## Patch Rationale

The patch preserves the existing single-block behavior and changes only the multi-block loop in both the SHAKE256 (rate=136) and SHAKE128 (rate=168) squeeze functions. It guards the permutation with `if (i0 > 0)`, so:

- block 0 is squeezed directly from the finalized state;
- blocks 1 and later are preceded by exactly one Keccak permutation;
- the existing trailing partial-block permutation remains correct after all full blocks have been emitted.

## Residual Risk

These functions are currently unreachable dead code in the ML-KEM implementation. The fix is a correctness improvement for the shipped library code.

## Patch

```diff
diff --git a/usr.bin/ssh/libcrux_mlkem768_sha3.h b/usr.bin/ssh/libcrux_mlkem768_sha3.h
index 1e3dc45..51b268a 100644
--- a/usr.bin/ssh/libcrux_mlkem768_sha3.h
+++ b/usr.bin/ssh/libcrux_mlkem768_sha3.h
@@ -5046,7 +5046,9 @@ static KRML_MUSTINLINE void libcrux_sha3_generic_keccak_xof_squeeze_85_c7(
       size_t blocks = out_len / (size_t)136U;
       for (size_t i = (size_t)0U; i < blocks; i++) {
         size_t i0 = i;
-        libcrux_sha3_generic_keccak_keccakf1600_80_04(&self->inner);
+        if (i0 > (size_t)0U) {
+          libcrux_sha3_generic_keccak_keccakf1600_80_04(&self->inner);
+        }
         libcrux_sha3_simd_portable_squeeze_13_5b(
             &self->inner, out, i0 * (size_t)136U, (size_t)136U);
       }
@@ -5344,7 +5346,9 @@ static KRML_MUSTINLINE void libcrux_sha3_generic_keccak_xof_squeeze_85_49(
       size_t blocks = out_len / (size_t)168U;
       for (size_t i = (size_t)0U; i < blocks; i++) {
         size_t i0 = i;
-        libcrux_sha3_generic_keccak_keccakf1600_80_04(&self->inner);
+        if (i0 > (size_t)0U) {
+          libcrux_sha3_generic_keccak_keccakf1600_80_04(&self->inner);
+        }
         libcrux_sha3_simd_portable_squeeze_13_3a(
             &self->inner, out, i0 * (size_t)168U, (size_t)168U);
       }
```