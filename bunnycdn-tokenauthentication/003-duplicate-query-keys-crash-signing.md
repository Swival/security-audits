# Duplicate query keys crash signing

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `c#/BunnyCDN.TokenAuthentication/BunnyCDN.TokenAuthentication/TokenSigner.cs:35`
- `c#/BunnyCDN.TokenAuthentication/BunnyCDN.TokenAuthentication/TokenSigner.cs:42`
- `c#/BunnyCDN.TokenAuthentication/BunnyCDN.TokenAuthentication/TokenSigner.cs:106`

## Summary
`SignUrl` rejects valid URLs that contain repeated query parameter names. Query parsing routes through `ParseQueryString`, which stores decoded keys in a `Dictionary<string, string>` and throws on a duplicate key. As a result, inputs such as `?a=1&a=2` deterministically abort signing before parameter assembly or token generation.

## Provenance
- Verified from repository source and reproduced by code inspection of the signer flow.
- Scanner provenance: https://swival.dev

## Preconditions
- A caller passes a URL with at least one repeated query key to `SignUrl`.

## Proof
`SignUrl` constructs a `Uri` from `config.Url` and parses `uri.Query` before token generation. In `ParseQueryString`, each decoded key is inserted into a `Dictionary<string, string>`. The implementation explicitly checks `ContainsKey` and throws `ArgumentException` when the same key appears again. Therefore, a URL like `https://example.test/file?a=1&a=2` always fails during parsing and never reaches `BuildParameters` or signing output.

## Why This Is A Real Bug
Repeated query keys are valid and common in real URLs. The validator does not reject or normalize them beforehand, so this crash is reachable through normal API use. Because failure happens before signing completes, any consumer that forwards user- or upstream-supplied URLs can be forced into a reliable signing failure, causing denial of service for those requests.

## Fix Requirement
Preserve duplicate query keys during parsing and signing instead of treating them as an exception condition.

## Patch Rationale
The patch changes query handling to retain repeated parameters rather than storing them in a uniqueness-enforcing dictionary. This matches URL semantics, allows signing to proceed for valid inputs, and avoids introducing validation-only behavior that would continue to reject common query shapes.

## Residual Risk
None

## Patch
- Patch file: `003-duplicate-query-keys-crash-signing.patch`
- Intended change: update `c#/BunnyCDN.TokenAuthentication/BunnyCDN.TokenAuthentication/TokenSigner.cs` so duplicate query keys are preserved through parsing and emitted during signing instead of throwing `ArgumentException`.