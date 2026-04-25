# Unsupported EKUs Panic

## Classification
Validation gap; denial of service. Severity: medium. Confidence: certain.

## Affected Locations
`src/crypto/x509/root_windows.go:228`

## Summary
Windows certificate verification panics when `VerifyOptions.KeyUsages` contains only unsupported EKUs and does not include `ExtKeyUsageAny`. Unsupported usages are skipped, producing a non-nil empty OID slice that is later indexed at `&oids[0]`.

## Provenance
Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions
Caller supplies `VerifyOptions` with only unsupported `KeyUsages` and no `ExtKeyUsageAny`.

## Proof
- `VerifyOptions.KeyUsages` reaches `systemVerify`.
- `systemVerify` reads caller-controlled usages at `src/crypto/x509/root_windows.go:213`.
- Because the usage slice is non-empty, default server-auth behavior is not applied.
- `oids := make([]*byte, 0, len(keyUsages))` creates a non-nil zero-length slice at `src/crypto/x509/root_windows.go:217`.
- Unsupported EKUs are absent from `windowsExtKeyUsageOIDs`, so no OID is appended at `src/crypto/x509/root_windows.go:223`.
- The `oids != nil` branch executes at `src/crypto/x509/root_windows.go:227`.
- `&oids[0]` at `src/crypto/x509/root_windows.go:230` indexes an empty slice and panics before `CertGetCertificateChain`.

## Why This Is A Real Bug
The API accepts caller-provided `VerifyOptions.KeyUsages`. Unsupported-only EKU input should produce a normal verification failure, such as `IncompatibleUsage`, or disable usage filtering according to intended semantics. Instead, it causes a runtime panic, allowing configurable or untrusted EKU input to crash a Windows process.

## Fix Requirement
Do not take `&oids[0]` unless `len(oids) > 0`. If no supported OIDs remain after filtering unsupported usages, return `IncompatibleUsage` or otherwise avoid configuring an empty `UsageIdentifiers` pointer.

## Patch Rationale
The patch in `041-unsupported-ekus-panic.patch` guards the Windows requested-usage setup so an empty OID slice is not indexed. This preserves normal handling for supported EKUs while converting unsupported-only usage input from a panic path into controlled verification behavior.

## Residual Risk
None

## Patch
`041-unsupported-ekus-panic.patch`