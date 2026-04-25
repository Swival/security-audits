# Negative inhibitPolicyMapping Accepted

## Classification

Validation gap. Severity: medium. Confidence: certain.

## Affected Locations

`src/crypto/x509/parser.go:743`

## Summary

`ParseCertificate` accepted a `policyConstraints` extension where `inhibitPolicyMapping` was encoded as a negative ASN.1 INTEGER. The value was decoded as signed `int64`, assigned to `Certificate.InhibitPolicyMapping`, and only checked for integer overflow. Negative values were not rejected, allowing malformed untrusted certificate DER to expose invalid certificate state.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Certificate DER contains a `policyConstraints` extension, OID `2.5.29.36`, with `inhibitPolicyMapping` encoded as a negative INTEGER.

## Proof

The reproduced malformed extension was:

```text
policyConstraints ::= SEQUENCE { [1] -1 }
DER: 30 03 81 01 ff
```

Runtime behavior before the patch:

```text
err=<nil>
InhibitPolicyMapping=-1 zero=false
```

The parser path stores untrusted extensions, calls `processExtensions`, decodes tag `[1]` using `ReadASN1Int64WithTag`, assigns the signed value to `out.InhibitPolicyMapping`, and only rejects values that overflow `int`.

`ReadASN1Int64WithTag` accepts signed ASN.1 INTEGER encodings, so the negative DER value is preserved and exposed.

## Why This Is A Real Bug

`Certificate.InhibitPolicyMapping` represents a non-negative skip count when present, while `-1` is used by the public API to mean unset. Accepting an explicitly encoded negative value collapses malformed certificate input into an internal sentinel state and violates the expected validation rules for `policyConstraints`.

Because certificate DER is attacker-controlled input in normal X.509 parsing flows, this is a practical validation gap rather than unreachable malformed state.

## Fix Requirement

Reject negative `requireExplicitPolicy` and `inhibitPolicyMapping` values before assigning them to certificate fields.

## Patch Rationale

The patch adds explicit `v < 0` validation after signed ASN.1 INTEGER decoding and before storing the parsed value. This preserves valid non-negative skip counts, keeps the existing integer overflow checks, and rejects malformed negative policy constraint values consistently.

## Residual Risk

None

## Patch

`061-negative-inhibitpolicymapping-accepted.patch`