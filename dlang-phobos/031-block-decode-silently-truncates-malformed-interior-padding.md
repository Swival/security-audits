# Block Decoder Accepts Invalid Interior Padding

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/base64.d:1021`
- `std/base64.d:818`

## Summary
The padded array-based Base64 decoder accepts malformed quartets where the third character is padding but the fourth character is not. In that path, decoding stops as soon as the third character decodes to `-1` (`'='`) and never validates the fourth character, so inputs such as `ab=c` and `ab=d` are silently truncated to a single decoded byte instead of being rejected with `Base64Exception`.

## Provenance
- Reproduced locally against the committed source.
- Reported via Swival Security Scanner: https://swival.dev

## Preconditions
- Caller decodes padded Base64 through the array-based `decode` overload.

## Proof
- `Base64.decode(source, buffer)` processes each 4-byte block in `std/base64.d:1021`.
- After decoding the first two Base64 characters, it writes the first output byte.
- It then evaluates the third character with `decodeChar(*srcptr++)`.
- When that third character is `=` and therefore decodes to `-1`, the implementation immediately `break`s.
- The fourth character is neither consumed nor checked in that branch.
- As a result, malformed padded quartets such as `ab=c` satisfy the existing length checks, decode to one byte, and return success.
- Local PoC confirmed:
  - `Base64.decode("ab=c")` returns `0x69` (`'i'`) instead of throwing.
  - `Base64.decode("ab=d")` also returns the same byte, confirming the fourth character is ignored once the third is `=`.

## Why This Is A Real Bug
The decoder is expected to reject malformed padded Base64, not normalize it into truncated output. Existing guards only enforce block-aligned length and derive output size from the last two source characters, so this malformed interior-padding case passes preflight and postconditions. That creates a real validation bypass for callers that treat successful decode as proof the input is valid Base64.

## Fix Requirement
When the third decoded character is padding, the decoder must require the fourth source character to exist and also be padding. If not, it must throw `Base64Exception`.

## Patch Rationale
The patch hardens the `v3 == -1` branch in `std/base64.d` so the decoder validates the final character of the quartet before accepting terminal padding. This preserves valid `xx==` handling while rejecting malformed forms like `ab=c` and `ab=d`, aligning runtime behavior with Base64 padding rules and caller expectations.

## Residual Risk
None

## Patch
- Patch file: `031-block-decode-silently-truncates-malformed-interior-padding.patch`
- Patched file: `std/base64.d`