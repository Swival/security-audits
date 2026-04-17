# Revoked-entry print errors are ignored

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `crypto/x509/t_crl.cc:77`

## Summary
- `X509_CRL_print` iterates revoked entries from `X509_CRL_get_REVOKED(x)`.
- In the revoked-entry loop, failures from `BIO_printf`, `i2a_ASN1_INTEGER`, `ASN1_TIME_print`, or `X509V3_extensions_print` hit an empty `if` body at `crypto/x509/t_crl.cc:77`.
- The function may still return success from the later signature-print path, so callers can receive a successful result even when revoked-entry output was omitted or truncated.

## Provenance
- Verified from the provided reproducer and source analysis.
- Scanner source: https://swival.dev

## Preconditions
- The CRL contains at least one revoked entry.
- A per-entry revoked-output operation fails.
- Later output, including final signature printing, succeeds.

## Proof
- `X509_CRL_print` obtains revoked entries with `X509_CRL_get_REVOKED(x)` and loops over them.
- At `crypto/x509/t_crl.cc:77`, the code checks several per-entry print operations in a combined condition, but the failure branch is empty.
- Because no error is returned or recorded there, iteration continues after a revoked-entry print failure.
- The reproducer established that BIO write failures need not be sticky: `o/bio/bio.cc:123` forwards to the BIO method each call, and custom BIOs created through `BIO_meth_new` / `BIO_meth_set_write` can fail selectively.
- Existing tree usage confirms this is practical: custom and partial-failure BIO patterns exist in `ssl/ssl_test.cc:10517` and `crypto/x509/x509_test.cc:3744`.
- Therefore, if one revoked-entry output operation fails but the final `X509_signature_print` succeeds, `X509_CRL_print` can still return success from `crypto/x509/t_crl.cc:105`.

## Why This Is A Real Bug
- The function’s return value is expected to reflect whether CRL printing succeeded.
- Ignoring revoked-entry print failures violates that contract by reporting success after incomplete output.
- The behavior is reachable with supported public BIO APIs and does not require undefined behavior or impossible state.

## Fix Requirement
- Return failure immediately when any revoked-entry print operation fails.

## Patch Rationale
- The patch changes the empty failure branch in the revoked-entry loop to propagate failure instead of ignoring it.
- This aligns revoked-entry handling with the rest of the function, where print failures already cause an error return.
- The fix is minimal and preserves successful behavior for fully printed CRLs.

## Residual Risk
- None

## Patch
- Patched in `028-revoked-entry-print-errors-are-ignored.patch`.
- The change updates `crypto/x509/t_crl.cc` so revoked-entry print failures cause `X509_CRL_print` to return failure immediately.