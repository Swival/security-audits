# Fragment dropped from signed URL output

## Classification
- Type: data integrity bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `go/token.go:126`

## Summary
`SignUrl` parses caller-supplied URLs with `url.Parse`, which stores any fragment in `parsed.Fragment`, but the function rebuilds the signed URL without re-attaching that fragment. As a result, inputs containing `#...` are returned as different client-visible URLs.

## Provenance
- Verified by reproduction against the current implementation in `go/token.go`
- Reproduced with a concrete PoC using a URL containing a fragment
- Scanner source: https://swival.dev

## Preconditions
- Caller signs a URL containing a fragment

## Proof
A minimal reproduction with input `https://example.b-cdn.net/video.mp4#chapter2` returns a signed URL of the form:
```text
https://example.b-cdn.net/video.mp4?token=...&expires=1598024587
```

The `#chapter2` suffix is missing. This follows directly from the implementation path:
- caller provides `rawUrl` with a fragment
- `url.Parse` stores the fragment in `parsed.Fragment`
- `SignUrl` reconstructs the output from scheme, host, path, tokenized query, and expiry
- no `#` plus `parsed.Fragment` is appended to the returned string

## Why This Is A Real Bug
Although URL fragments are not sent to BunnyCDN and do not affect server-side token validation, the function contract is still violated for fragment-bearing inputs. The returned signed URL no longer identifies the same client-visible resource state, breaking browser anchors and media fragments such as `#chapter2` or `#t=30`. This is directly reachable on every `SignUrl` call that receives a fragment.

## Fix Requirement
Append `#` plus `parsed.Fragment` when constructing the final signed URL.

## Patch Rationale
The patch preserves existing signing behavior for scheme, host, path, query, token, and expiry, and adds restoration of the parsed fragment only in the final returned URL. This fixes the data-loss issue without changing token generation semantics.

## Residual Risk
None

## Patch
Patch file: `004-fragment-is-dropped-from-signed-url-output.patch`