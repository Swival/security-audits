# Tail Decryption Over-Reads Ciphertext

## Classification

Vulnerability: medium severity. Confidence: certain.

## Affected Locations

`src/crypto/internal/fips140/aes/gcm/_asm/gcm/gcm_amd64_asm.go:1452`

## Summary

AES-GCM tail decryption performs a 16-byte vector load from the ciphertext tail pointer before masking unused bytes. When the remaining ciphertext length is 1..15 bytes, this reads past the logical end of `src` and can cross into unmapped or protected memory.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

AES-GCM decrypt is called with a ciphertext tail length of 1..15 bytes.

## Proof

After full ciphertext blocks are processed, `gcmAesDecTail` is reached when `ptxLen` is nonzero and less than 16. The generated assembly loads a full 16-byte block from `ctx` with `MOVOU(Mem{Base: ctx}, B0)` before applying the length mask. The mask is therefore too late to prevent the out-of-bounds read.

The reproducer confirmed the generated source and assembly behavior:

- `src/crypto/internal/fips140/aes/gcm/_asm/gcm/gcm_amd64_asm.go:1415` performs the 16-byte load from `ctx`.
- `src/crypto/internal/fips140/aes/gcm/_asm/gcm/gcm_amd64_asm.go:1416` applies the mask afterward.
- Public trigger: `cipher.NewGCMWithTagSize(aesBlock, 12)` with `Open` input containing 1 byte of ciphertext and a 12-byte tag leaves only 13 bytes readable from `ctx`, while the assembly reads 16 bytes.
- Tag sizes 13 and 14 are also affected for sufficiently short ciphertext tails.

## Why This Is A Real Bug

The ciphertext length is caller-controlled. A valid Go slice can be backed by memory ending at a page boundary, such as an mmap-backed or unsafe-created slice. The unconditional 16-byte load can cross into an unmapped or protected page and fault before authentication completes. Even without a fault, the implementation reads beyond the logical source buffer and, for short tags, beyond the complete input.

## Fix Requirement

Tail decryption must not perform any 16-byte load from `src` unless at least 16 bytes are available. For tails shorter than 16 bytes, it must load only the present bytes, such as by bytewise loading into a temporary vector/buffer before decryption and masking.

## Patch Rationale

The patch changes tail handling so the partial ciphertext block is assembled safely from the actual remaining bytes before any vector operation consumes it. This preserves the existing AES-GCM tail behavior while removing the out-of-bounds read.

## Residual Risk

None

## Patch

`031-tail-decryption-over-reads-ciphertext.patch`