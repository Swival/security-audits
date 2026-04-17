# Missing `DEK-Info` delimiter validation before IV parsing

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `crypto/pem/pem_lib.cc:315`

## Summary
`PEM_get_EVP_CIPHER_INFO` advances past the cipher name and increments the `DEK-Info` cursor before IV parsing without first verifying that the next byte is the required comma delimiter. As reproduced, malformed PEM headers using a non-token separator such as `:` are accepted and decrypted successfully with the same IV as a well-formed header. This is input-validation leniency that causes malformed `DEK-Info` syntax to be parsed as valid.

## Provenance
- Verified from the reported implementation behavior in `crypto/pem/pem_lib.cc:315`
- Reproduced with malformed PEM input that decrypts successfully despite using `:` instead of `,`
- Reference: https://swival.dev

## Preconditions
- Attacker controls PEM header bytes

## Proof
A reachable malformed `DEK-Info` header is accepted:
```text
DEK-Info: AES-128-CBC:B3B2...
```

Observed behavior:
- Well-formed `DEK-Info: AES-128-CBC,B3B2...` decrypts successfully
- Malformed `DEK-Info: AES-128-CBC:B3B2...` also decrypts successfully

Code behavior described by reproduction:
- The parser scans the algorithm token
- It then does `header++` at `crypto/pem/pem_lib.cc:315`
- No check ensures `*header == ','` before advancing
- IV parsing then starts from the next byte, so a non-token separator like `:` is treated as acceptable syntax

Important narrowing confirmed during reproduction:
- It is not true that any arbitrary single byte works
- If the substituted byte is itself valid as part of the cipher token, parsing continues as part of the cipher name and the header is rejected as unsupported encryption
- Example: `AES-128-CBCXB3...` fails with `PEM_R_UNSUPPORTED_ENCRYPTION`

## Why This Is A Real Bug
The PEM `DEK-Info` field requires a delimiter between the cipher name and IV. Accepting malformed syntax violates the parser's own expected format and creates a real discrepancy between syntactic validity and runtime behavior. The issue is directly reachable on attacker-controlled PEM input and was demonstrated with successful decryption of malformed input, so this is not merely theoretical. The impact is confined to validation leniency and syntax confusion, but the acceptance of invalid structured input is itself a correctness bug.

## Fix Requirement
Reject `DEK-Info` headers unless the byte following the parsed cipher name is exactly `,` before advancing to IV parsing. On mismatch, return a parse error rather than attempting to decode the IV.

## Patch Rationale
The patch adds an explicit delimiter check at the transition point between cipher-name parsing and IV decoding in `crypto/pem/pem_lib.cc`. This enforces the documented/expected `DEK-Info` grammar, preserves behavior for valid inputs, and converts previously accepted malformed headers into clean parse failures. The change is minimal and scoped to the faulty acceptance condition.

## Residual Risk
None

## Patch
- Patch file: `026-missing-delimiter-check-before-iv-parsing.patch`
- Change: require `*header == ','` before incrementing the pointer and calling IV parsing in `crypto/pem/pem_lib.cc`
- Result: malformed headers such as `DEK-Info: AES-128-CBC:B3B2...` are rejected instead of being parsed as valid