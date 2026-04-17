# Negative bit index reads before buffer start

## Classification
- Type: vulnerability
- Severity: medium
- Confidence: certain

## Affected Locations
- `crypto/asn1/a_bitstr.cc:199`

## Summary
`ASN1_BIT_STRING_get_bit` accepts a signed bit index and computes the byte offset before validating that the index is non-negative. For `n <= -8`, the computed offset is negative and the function reads `a->data[w]` before the start of the buffer. This is reachable through the public API.

## Provenance
- Report reproduced and patched from a verified finding
- Scanner: [Swival Security Scanner](https://swival.dev)

## Preconditions
- Caller passes a negative bit index to `ASN1_BIT_STRING_get_bit`
- `a` is non-null, `a->data` is non-null, and the bit string has at least one byte

## Proof
- `ASN1_BIT_STRING_get_bit` takes signed `int n` and computes `w = n / 8`
- With `n = -8`, C++ integer division yields `w = -1`
- The existing guard rejects only null pointers or `a->length < (w + 1)`; for `w = -1`, this becomes `a->length < 0`, which is false for valid objects
- Execution reaches `a->data[-1]`, causing an out-of-bounds read before the buffer start
- Reproduced by building ASan `crypto_test`, then compiling a small PoC against `/tmp/boringssl-asan/libcrypto.a` that allocates a 1-byte `ASN1_BIT_STRING` and calls `ASN1_BIT_STRING_get_bit(s, -8)`
- AddressSanitizer reports an invalid read in `ASN1_BIT_STRING_get_bit`, confirming the bug
- Negative indices in `[-1, -7]` do not move before the allocation because division truncates toward zero, but they are still incorrectly accepted; the memory-safety impact is for `n <= -8`

## Why This Is A Real Bug
The vulnerable path is exposed through the exported function declaration in `include/openssl/asn1.h`, so external callers can supply a negative index directly. The existing bounds check is insufficient because it validates length against a value derived from the already-negative offset. This results in a real pre-buffer read under a valid, minimal object state and is not blocked by internal invariants.

## Fix Requirement
Reject negative bit indices before computing or using the byte offset in bit access helpers, including both getter and setter paths.

## Patch Rationale
The patch adds an explicit `n < 0` rejection in the bit get/set helpers in `crypto/asn1/a_bitstr.cc`, making negative indices invalid before any offset calculation occurs. This is the narrowest safe fix because it preserves existing behavior for valid callers while eliminating both the confirmed pre-buffer read in the getter and the analogous invalid index handling in the setter.

## Residual Risk
None

## Patch
- Patch file: `022-negative-bit-index-reads-before-buffer-start.patch`
- Change: add early negative-index validation in the ASN.1 bit-string bit access helpers in `crypto/asn1/a_bitstr.cc`