# Signed token can be removed from output URL

## Classification
- Type: vulnerability
- Severity: high
- Confidence: certain

## Affected Locations
- `nodejs/token.js:44`
- `nodejs/token.js:101`

## Summary
Non-directory URL signing accepts caller-supplied query keys named `token` and `expires`, then appends newly generated `token` and `expires` fields around the preserved original query tail. This produces output URLs with duplicate reserved keys, allowing the caller-controlled values to remain in the signed URL and potentially override the generated authentication fields depending on downstream query parsing.

## Provenance
- Verified finding reproduced from scanner report
- Source: Swival Security Scanner, `https://swival.dev`

## Preconditions
- Caller signs a non-directory URL containing a `token` query parameter

## Proof
`parsed.searchParams` is copied into `queryParams`, then into `parameters`, `sortedEntries`, and `urlData` in `nodejs/token.js`. For non-directory URLs, the final URL is constructed by emitting a generated `token`, then appending `tail`, then appending a generated `expires`. Because `tail` is derived from attacker-controlled query parameters, an input like `?token=attacker` survives into the output as a second `token` field. Existing duplicate detection only rejects duplicates already present in the input and does not reject collisions with reserved output keys. This was reproduced and confirms malformed signed URL generation with duplicate authentication parameters.

## Why This Is A Real Bug
The signer is expected to produce a canonical authenticated URL. Emitting duplicate reserved authentication keys violates that invariant and creates parser-dependent behavior at verification time. Even without proving the CDN's exact duplicate-key resolution, the library deterministically generates ambiguous signed URLs from untrusted input, which is sufficient to establish a real security-impacting bug in signing logic.

## Fix Requirement
Reject or strip reserved query keys used by the signer, specifically `token` and `expires`, before building the canonical parameter set and output URL.

## Patch Rationale
The patch removes the ambiguity at the source by preventing caller-controlled reserved keys from entering the signed parameter flow. This preserves canonical URL generation, avoids duplicate authentication fields, and ensures generated `token` and `expires` remain the only authoritative values in the output.

## Residual Risk
None

## Patch
- Patch file: `007-signed-token-can-be-removed-from-output-url.patch`
- Patched file: `nodejs/token.js`