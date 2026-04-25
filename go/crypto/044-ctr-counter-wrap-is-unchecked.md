# CTR Counter Wrap Is Unchecked

## Classification
High severity vulnerability. Confidence: certain.

## Affected Locations
`src/crypto/internal/fips140/aes/ctr.go:77`

## Summary
AES-CTR counter advancement did not detect 128-bit counter overflow. A caller-controlled IV near `2^128 - 1` plus sufficient input length caused the counter to wrap to zero, reusing keystream blocks under the same key and breaking CTR confidentiality.

## Provenance
Verified from the supplied finding and reproduced behavior. Source: Swival Security Scanner, https://swival.dev

## Preconditions
Caller can control or influence the CTR IV/counter value and request enough keystream to cross the `2^128` counter boundary.

## Proof
`NewCTR` loads the IV into `ivhi:ivlo`. `XORKeyStreamAt` derives the starting counter with `add128` and advances it while processing caller-controlled `src` length. The previous `add128` behavior discarded carry out of the high limb, so `ivhi:ivlo` silently wrapped.

Concrete reproduction:
- AES key: all zero bytes.
- IV A: all `0xff`.
- IV B: all `0x00`.
- Encrypt at least 32 bytes with IV A.
- The second block under IV A uses wrapped counter `0`.
- That keystream block equals the first block produced under IV B with the same key.

This confirms keystream reuse across wrapped high-IV traffic and low-IV traffic.

## Why This Is A Real Bug
CTR mode requires each key/counter block input to be unique. Silent counter wrap violates that invariant. Reused keystream lets an attacker XOR ciphertexts to recover XOR of plaintexts, and known plaintext in one stream recovers plaintext from the other.

## Fix Requirement
Detect carry out of the 128-bit counter during initial offset calculation and subsequent counter advancement. Panic before encrypting any block that would require a wrapped counter value.

## Patch Rationale
The patch rejects counter ranges that cross `2^128` instead of allowing silent wrap. This preserves CTR’s uniqueness requirement and prevents generation of repeated keystream blocks under the same key.

## Residual Risk
None

## Patch
`044-ctr-counter-wrap-is-unchecked.patch`