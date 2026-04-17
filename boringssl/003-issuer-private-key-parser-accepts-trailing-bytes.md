# Issuer private key parser accepts trailing bytes

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `crypto/trust_token/pmbtoken.cc:272`

## Summary
`bssl::pmbtoken_*_issuer_key_from_bytes` accepts serialized issuer private keys with extra trailing bytes. The parser consumes exactly six fixed-width scalars, recomputes the public key from those scalars, and returns success without verifying full input consumption. Distinct byte strings therefore deserialize to the same issuer key.

## Provenance
- Verified from the provided reproducer and patch context.
- Reference: https://swival.dev

## Preconditions
- Attacker controls serialized issuer private key bytes.

## Proof
- `bssl::pmbtoken_*_issuer_key_from_bytes` forwards untrusted `in,len` into `pmbtoken_issuer_key_from_bytes`.
- `pmbtoken_issuer_key_from_bytes` iterates six times and uses `CBS_get_bytes` to read one scalar per iteration.
- After the sixth scalar, the function does not check `CBS_len(&cbs) == 0`.
- Reproducer output shows both canonical and extended encodings are accepted:
```text
priv_key_len=292 ok_orig=1 ok_extended=1
```
- For PMB issuer keys, the private encoding is six P-384 scalars after the 4-byte key ID. Any appended suffix is ignored, while the same public key is recomputed from only the first six scalars.

## Why This Is A Real Bug
The parser claims success for malformed non-canonical inputs. That creates ambiguous private-key encodings on every issuer-key import path using this helper. Under the stated precondition, an attacker can supply oversized serialized keys that are treated as valid and equivalent to their canonical form, violating strict input validation and canonical parsing expectations.

## Fix Requirement
Reject serialized issuer private keys unless all bytes are consumed after parsing the six expected scalars.

## Patch Rationale
The patch adds a final exhaustion check in `pmbtoken_issuer_key_from_bytes` so deserialization fails when trailing bytes remain. This enforces a single canonical encoding for issuer private keys and aligns acceptance with the actual parsed structure.

## Residual Risk
None

## Patch
- Patch file: `003-issuer-private-key-parser-accepts-trailing-bytes.patch`
- Change: add a `CBS_len(&cbs) == 0` validation after the six-scalar parse loop in `crypto/trust_token/pmbtoken.cc`, returning failure if trailing bytes remain.