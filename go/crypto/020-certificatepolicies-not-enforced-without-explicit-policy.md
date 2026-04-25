# CertificatePolicies Not Enforced Without Explicit Policy

## Classification

Validation gap. Severity: medium. Confidence: certain.

## Affected Locations

`src/crypto/x509/verify.go:1416`

## Summary

`VerifyOptions.CertificatePolicies` is not enforced unless explicit policy processing is required. A caller can request acceptable certificate policies, but `policiesValid` may still accept a chain when the resulting user-constrained policy set is empty and `explicitPolicy` remains positive.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

Caller sets `VerifyOptions.CertificatePolicies` without also requiring explicit policy.

## Proof

User-supplied `VerifyOptions.CertificatePolicies` reaches `policiesValid` through `Verify`.

When the chain lacks acceptable policies, or lacks certificate policies entirely, the policy graph can become nil and the user-constrained policy set can become empty. The prior final failure condition was gated by `explicitPolicy == 0`. With default policy constraints, `explicitPolicy` remains positive, so `policiesValid` returned true despite no acceptable requested policy being present.

The existing tests encoded this behavior: a chain was accepted when the caller requested `testOID3` even though the chain was only valid for other policy OIDs.

## Why This Is A Real Bug

`CertificatePolicies` is caller-supplied validation policy. If a caller configures it, accepted chains must contain at least one acceptable policy. Silently accepting a chain with no matching policy violates the caller’s constraint and can bypass application-level policy restrictions.

## Fix Requirement

Reject an empty user-constrained policy set whenever `VerifyOptions.CertificatePolicies` is non-empty, regardless of whether `explicitPolicy` reached zero.

## Patch Rationale

The patch makes caller-requested certificate policies authoritative. It preserves explicit policy handling for RFC policy processing while ensuring that a non-empty caller constraint cannot be satisfied by an empty result set.

Patch file: `020-certificatepolicies-not-enforced-without-explicit-policy.patch`

## Residual Risk

None

## Patch

`020-certificatepolicies-not-enforced-without-explicit-policy.patch` enforces failure when `CertificatePolicies` is non-empty and policy intersection produces no acceptable policies.