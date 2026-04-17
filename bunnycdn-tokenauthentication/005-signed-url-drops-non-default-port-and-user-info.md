# Signed URL drops non-default port and user info

## Classification
- Type: data integrity bug
- Severity: high
- Confidence: certain

## Affected Locations
- `java/src/main/java/BunnyCDN/TokenSigner.java:141`

## Summary
- `signUrl(...)` parses the caller-provided URL with `new URI(url)` but reconstructs the signed URL from `uri.getScheme() + "://" + uri.getHost()`.
- That reconstruction discards both `uri.getUserInfo()` and `uri.getPort()`.
- For inputs such as `https://user@example.com:8443/file.txt?x=1`, the signed output becomes `https://example.com/file.txt?...`, changing the authority and no longer representing the original target.

## Provenance
- Verified from repository source and reproduced by code-path inspection in the local worktree.
- Cross-implementation comparison shows intended behavior in `c#/BunnyCDN.TokenAuthentication/BunnyCDN.TokenAuthentication/TokenSigner.cs:44`, which preserves full authority.
- Scanner provenance: https://swival.dev

## Preconditions
- Caller signs a URL containing non-default port or user info.

## Proof
- `signUrl(...)` parses the input as a `URI`.
- Final URL composition uses scheme plus host, then appends path and query components.
- No branch appends `uri.getPort()` or `uri.getUserInfo()`.
- Therefore, any signed URL with user info and/or a non-default port is deterministically rewritten to a different authority.
- Example: input `https://user@example.com:8443/file.txt?x=1` yields a signed URL rooted at `https://example.com/...`, dropping `user@` and `:8443`.

## Why This Is A Real Bug
- The function claims to sign the caller's URL but instead mutates the destination authority.
- This breaks integrity of the signed URL and can redirect consumers to a different origin tuple than requested.
- The behavior is reachable through every `signUrl(...)` overload because they funnel into the same implementation and do not reject such URLs.

## Fix Requirement
- Rebuild the signed URL using the original URI authority so user info and port are preserved.
- Keep existing signing behavior for path and query handling unchanged aside from preserving the original authority.

## Patch Rationale
- The patch composes the final URL from the parsed URI authority instead of host alone.
- This preserves `userInfo@host:port` exactly as provided by the parsed input while minimizing behavioral change to the rest of the signing logic.
- The change aligns Java behavior with the existing C# implementation.

## Residual Risk
- None

## Patch
- Patch file: `005-signed-url-drops-non-default-port-and-user-info.patch`
- Patched location: `java/src/main/java/BunnyCDN/TokenSigner.java`
- Effective change: replace host-only reconstruction with authority-preserving reconstruction when composing the signed URL.