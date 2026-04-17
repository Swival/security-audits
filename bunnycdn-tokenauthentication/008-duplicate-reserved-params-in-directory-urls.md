# Duplicate reserved params in directory URLs

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `nodejs/token.js:44`

## Summary
In directory mode, `signUrl` serializes caller-controlled query parameters into the returned URL and then also injects reserved signing fields, `bcdn_token` and `expires`, without rejecting those names first. If the input URL already contains either reserved parameter, the output contains duplicate signing fields and becomes ambiguous or non-canonical.

## Provenance
- Reproduced from the verified finding and patch target in `nodejs/token.js`
- Reference: https://swival.dev

## Preconditions
- Caller invokes directory signing mode
- Input URL already contains `expires` or `bcdn_token` in its query string

## Proof
- `signUrl` parses the input URL into `queryParams` and only checks for duplicate keys already present in the original query.
- In directory mode, it always returns a path prefixed with `bcdn_token=<token>` and suffixed with `expires=<ts>`, while preserving caller-provided query parameters.
- This allows direct duplication of reserved fields:
  - Input: `https://example.b-cdn.net/dir/?expires=111`
  - Output: `https://example.b-cdn.net/bcdn_token=HS256-...&expires=111&expires=1598024587/dir/`
  - Input: `https://example.b-cdn.net/dir/?bcdn_token=abc`
  - Output: `https://example.b-cdn.net/bcdn_token=HS256-...&bcdn_token=abc&expires=1598024587/dir/`

## Why This Is A Real Bug
The signed message is computed using the internally generated expiry value, but the emitted directory URL can contain multiple `expires` or `bcdn_token` fields. Consumers that parse first-value, last-value, or reject duplicates will interpret the signed URL differently or fail validation entirely. This breaks signed URL generation for valid callers and creates inconsistent downstream behavior.

## Fix Requirement
Reject caller-supplied `expires` and `bcdn_token` when `isDirectory` is true, or remove/overwrite those parameters before serializing the returned URL so reserved signing fields are unique.

## Patch Rationale
The patch in `008-duplicate-reserved-params-in-directory-urls.patch` enforces reserved-parameter handling for directory URLs before output assembly, preventing duplicate `expires` and `bcdn_token` fields and ensuring the final URL matches the signing context.

## Residual Risk
None

## Patch
- `008-duplicate-reserved-params-in-directory-urls.patch`