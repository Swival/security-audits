# CRL Issuer Key Not Enforced

## Classification

Validation gap; severity medium; confidence certain.

## Affected Locations

`src/crypto/x509/x509.go:2217`

## Summary

`CreateRevocationList` accepts an issuer certificate and a private signer independently, but did not verify that `priv.Public()` matches `issuer.PublicKey`. This allowed callers to generate a CRL whose declared issuer and Authority Key Identifier came from one certificate while the CRL signature was produced by an unrelated private key.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Caller controls both arguments passed to `CreateRevocationList`:

- `issuer`
- `priv`

## Proof

`CreateRevocationList` validates issuer key usage, subject key ID, validity dates, CRL number, and derives the CRL issuer DN and AKI from `issuer`.

Before the patch, it did not perform the equivalent of the certificate creation key-pair consistency check. The function proceeded to select signing parameters from `priv` and sign the TBSCertList with `priv`, while the resulting CRL still declared `issuer` as the issuer.

Observed invariant failure:

- `tbsCertList.Issuer` is derived from `issuer`
- `tbsCertList.AuthorityKeyId` is derived from `issuer.SubjectKeyId`
- the signature is produced by `priv`
- `priv.Public()` may not equal `issuer.PublicKey`

The generated CRL then fails verification with the declared issuer via `RevocationList.CheckSignatureFrom(issuer)`.

## Why This Is A Real Bug

This is a real generation-time validation gap. The public API documents and implies that `priv` is the private key corresponding to the issuer certificate, but previously accepted mismatched issuer/signer pairs.

This does not let an attacker forge a CRL that correct relying parties should accept, because signature verification against the declared issuer fails. The bug is that the CRL generation API emits an internally inconsistent object instead of rejecting invalid inputs.

## Fix Requirement

Before signing, compare `priv.Public()` with `issuer.PublicKey` and reject mismatches.

## Patch Rationale

The patch adds a public/private key consistency check to `CreateRevocationList`, matching the invariant already enforced by certificate creation. Rejecting mismatches before signing prevents emission of CRLs whose declared issuer did not actually sign the TBSCertList.

## Residual Risk

None

## Patch

`007-crl-issuer-key-not-enforced.patch`