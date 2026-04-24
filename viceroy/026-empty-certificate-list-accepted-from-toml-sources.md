# Empty TOML client certificate chains bypass validation

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/config/backends/client_cert_info.rs:139`
- `src/config/backends/client_cert_info.rs:149`
- `src/config/backends/client_cert_info.rs:152`

## Summary
TOML-backed `client_certificate` parsing accepts `Some(Vec::new())` as a valid certificate chain when the key parses successfully but the certificate input contains zero PEM certificates. This allows configuration loading to succeed with an unusable client certificate instead of returning `NoCertsFound`.

## Provenance
- Verified from the provided reproducer and source analysis in the checked-out project
- Scanner reference: https://swival.dev

## Preconditions
- A TOML `client_certificate` block provides a parseable private key
- The `certificate` or `certificate_file` field contains data that yields zero PEM certificates

## Proof
`certificate` and `certificate_file` inputs flow into `read_certificates`, which returns `Ok(Vec::new())` when `rustls_pemfile::certs` finds no certificates. In TOML conversion, the match only rejects missing certificates, not empty ones, so `(Some(vec![]), Some(key))` reaches `ClientCertInfo` construction.

A confirmed reproducer used a valid RSA key with:
```toml
certificate = """not a pem certificate"""
```

`FastlyConfig::from_str` accepted the backend configuration, and `backend.client_cert.as_ref().unwrap().certs().len()` evaluated to `0`, proving an empty chain was stored as configured client certificate data.

## Why This Is A Real Bug
The code intends to reject certificate-less client certificate configurations via `NoCertsFound`, but TOML parsing skips that guarantee for the empty-vector case. The resulting `ClientCertInfo` is later treated as present by upstream TLS setup, so invalid configuration is accepted at load time and only fails later during connection handling. That is a real validation failure and behavior regression against expected config semantics.

## Fix Requirement
Reject empty certificate vectors during TOML parsing before constructing `ClientCertInfo`, and return the existing `NoCertsFound` error path for this case.

## Patch Rationale
The patch adds an explicit emptiness check in the TOML `TryFrom<toml::Value>` path in `src/config/backends/client_cert_info.rs`, ensuring TOML-sourced certificate data follows the same non-empty invariant already expected for valid client certificate configuration. This keeps behavior localized, preserves existing error semantics, and prevents invalid `ClientCertInfo` instances from being created.

## Residual Risk
None

## Patch
- Patch file: `026-empty-certificate-list-accepted-from-toml-sources.patch`