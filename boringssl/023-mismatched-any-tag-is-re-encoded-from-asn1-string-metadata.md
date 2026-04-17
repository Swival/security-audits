# Mismatched ANY tag re-encodes from ASN1_STRING metadata

## Classification
- Type: data integrity bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `crypto/asn1/a_type.cc:337`
- `crypto/x509/x_algor.cc:148`
- `crypto/x509/x_algor.cc:173`

## Summary
`bssl::asn1_marshal_any` accepts an explicit ANY tag from `ASN1_TYPE.type`, but for string-like payloads the encoder reused `ASN1_STRING.type` metadata instead of the supplied tag. A mismatched `ASN1_TYPE` therefore serialized with the inner string tag, corrupting emitted DER. This is reproducible through `X509_ALGOR` parameter encoding.

## Provenance
- Verified by local reproduction against the checked-out commit and patch validation.
- Scanner origin: [Swival Security Scanner](https://swival.dev)

## Preconditions
- Attacker controls an `ASN1_TYPE` whose outer `ASN1_TYPE.type` differs from `value.asn1_string->type`.
- The object is serialized through `bssl::asn1_marshal_any`, such as `X509_ALGOR` parameter encoding.

## Proof
A PoC constructed an `X509_ALGOR` with parameter ANY outer type `V_ASN1_OCTET_STRING` (`4`) and inner string type `V_ASN1_UTF8STRING` (`12`). Serializing with `i2d_X509_ALGOR` produced:
```text
300e06092a864886f70d0101010c0141
```
The final field encoded as tag `0x0c` (`UTF8String`) instead of the requested `0x04` (`OCTET STRING`), proving `asn1_marshal_any` re-emitted the inner `ASN1_STRING` tag.

I also verified scope: generic `i2d_ASN1_TYPE` does not use this path and encoded the same mismatched object as `040141`, so the issue is real but limited to callers that route through `bssl::asn1_marshal_any`.

## Why This Is A Real Bug
`ASN1_TYPE_set` and `ASN1_TYPE_set1` permit `ASN1_TYPE.type` and `ASN1_STRING.type` to diverge. When serialization uses the wrong source of truth, the emitted DER no longer matches the caller-selected ANY tag. That changes wire-visible semantics and can break downstream parsing, comparison, signature coverage assumptions, or policy handling for encoded algorithm parameters.

## Fix Requirement
String-like ANY encoding must honor the explicit `type` argument passed into the marshal path, not `ASN1_STRING.type`, when choosing the output ASN.1 tag.

## Patch Rationale
The patch updates `crypto/asn1/a_type.cc` so octet/string-like branches in `asn1_marshal_string_with_type` encode with the function's `type` parameter rather than `in->type`. This preserves caller-selected ANY tags while leaving payload bytes unchanged. The change is minimal and directly aligns encoding behavior with `asn1_marshal_any`'s contract.

## Residual Risk
None

## Patch
- Patch file: `023-mismatched-any-tag-is-re-encoded-from-asn1-string-metadata.patch`
- Changed logic in `crypto/asn1/a_type.cc:337` to use the passed `type` value for string-like tag emission during ANY marshaling.