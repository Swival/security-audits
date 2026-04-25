# Negative requireExplicitPolicy Accepted

## Classification

Validation gap; medium severity; confidence: certain.

## Affected Locations

`src/crypto/x509/parser.go:731`

## Summary

The X.509 parser accepts a negative `requireExplicitPolicy` value in the policy constraints extension. `SkipCerts ::= INTEGER (0..MAX)` must be non-negative, but the parser only checked integer overflow before assigning the decoded value.

## Provenance

Verified from the supplied finding and reproducer. Source: Swival Security Scanner, https://swival.dev

## Preconditions

Parsing a v3 certificate containing a policy constraints extension with OID `2.5.29.36`.

## Proof

DER certificate extensions reach `processExtensions`, where OID `2.5.29.36` is parsed as policy constraints.

For tag `[0] requireExplicitPolicy`, `ReadASN1Int64WithTag` accepts a signed `int64`. The parser then assigns the decoded value to `out.RequireExplicitPolicy` and only checks whether the value overflows `int`.

No `v < 0` validation existed, so a DER INTEGER such as `-1` could populate `Certificate.RequireExplicitPolicy` instead of causing certificate parsing to fail.

## Why This Is A Real Bug

RFC policy constraints define `SkipCerts ::= INTEGER (0..MAX)`, so negative values are invalid.

Accepting a negative value causes a malformed policy constraints extension, including a critical one, to be treated as successfully handled. Later verification logic treats negative `RequireExplicitPolicy` values as unset because it only applies the constraint when `RequireExplicitPolicy > 0` or `RequireExplicitPolicyZero` is true.

## Fix Requirement

Reject negative decoded values for `[0] requireExplicitPolicy` before assigning them to `Certificate.RequireExplicitPolicy`.

## Patch Rationale

The patch adds an explicit `v < 0` validation check in the policy constraints parsing path. This enforces the ASN.1 `0..MAX` constraint at parse time and preserves existing overflow protection.

## Residual Risk

None

## Patch

`060-negative-requireexplicitpolicy-accepted.patch`