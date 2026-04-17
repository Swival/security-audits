# Duplicate query keys block ignore-params signing

## Classification
- Type: logic error
- Severity: medium
- Confidence: certain

## Affected Locations
- `java/src/main/java/BunnyCDN/TokenSigner.java:68`
- `java/src/main/java/BunnyCDN/TokenSigner.java:78`
- `java/src/main/java/BunnyCDN/TokenSigner.java:136`

## Summary
When `signUrl(...)` receives a URL whose query string contains repeated parameter names, query parsing inserts decoded keys into a `TreeMap<String,String>` and throws `IllegalArgumentException` on the second occurrence. This happens before the `ignoreParams=true` path replaces the original query with only `token_ignore_params=true`, so valid URLs become unsignable even though the caller explicitly asked to ignore query parameters.

## Provenance
- Verified from the provided source and reproducer summary
- Scanner origin: https://swival.dev

## Preconditions
- The input URL contains repeated query parameter names
- The caller invokes a public `signUrl(...)` overload with `ignoreParams=true`

## Proof
At `java/src/main/java/BunnyCDN/TokenSigner.java:68`, attacker- or caller-controlled `url` is accepted by a public `signUrl(...)` overload.
At `java/src/main/java/BunnyCDN/TokenSigner.java:78`, `uri.getRawQuery()` is parsed into key/value pairs and stored in `TreeMap<String,String> queryParams`; a duplicate decoded key triggers `IllegalArgumentException("Duplicate query parameter: ...")`.
At `java/src/main/java/BunnyCDN/TokenSigner.java:136`, the `ignoreParams` branch later discards the parsed query and replaces it with only `token_ignore_params=true`.
Therefore a URL like `https://example.com/file?a=1&a=2` causes signing to abort before the code reaches the branch that ignores all original query parameters.

## Why This Is A Real Bug
The failing input is a syntactically valid URL, and duplicate query keys are common in real HTTP traffic. In the affected execution path, original query parameters are intentionally excluded from signing, so rejecting the URL because of duplicate query keys is inconsistent with the method's own semantics. This creates a reachable denial of functionality for legitimate callers using `ignoreParams=true`.

## Fix Requirement
Short-circuit query parsing when `ignoreParams=true`, or otherwise avoid duplicate-key validation on a query that will be discarded. The implementation must allow signing to proceed for URLs with repeated query parameter names when query parameters are being ignored.

## Patch Rationale
The patch in `006-duplicate-query-keys-are-rejected-instead-of-preserved.patch` addresses the reproduced bug by preventing duplicate-query rejection from running on the `ignoreParams=true` path. That matches existing signing behavior for ignored queries and removes the erroneous dependency on parseability of data that is not used.

## Residual Risk
None

## Patch
`006-duplicate-query-keys-are-rejected-instead-of-preserved.patch`