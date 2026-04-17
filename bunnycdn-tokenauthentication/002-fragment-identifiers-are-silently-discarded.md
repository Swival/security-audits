# Fragment identifiers are silently discarded

## Classification
- Type: data integrity bug
- Severity: low
- Confidence: certain

## Affected Locations
- `rust/src/lib.rs:116`

## Summary
`sign_url` rebuilds the output URL from parsed components but never restores the original fragment. Any input URL containing `#...` is returned without that fragment, silently changing caller-supplied data.

## Provenance
- Verified from the provided reproduction and code inspection in `rust/src/lib.rs`
- Reproduced locally against the committed crate
- Scanner source: https://swival.dev

## Preconditions
- The input URL passed to `sign_url` includes a fragment identifier

## Proof
- `sign_url` parses `raw_url` with `Url::parse`
- Final assembly uses scheme, host, path, and rebuilt query data, but does not append `parsed.fragment()`
- For example, signing `https://example.com/file.png?x=1#frag` returns:
```text
https://example.com/file.png?token=HS256-xlrSjBSX8GQbzDxVDCqcswV9_zJe7EeBTe37pcjuiaU&x=1&expires=123
```
- The original `#frag` is missing, and no reachable branch restores it

## Why This Is A Real Bug
Fragments are part of the caller-provided URL string. Even though they are not sent in HTTP requests, applications rely on them for anchors, media offsets, client-side routing, and UI state. Dropping the fragment makes the API return a different URL than it was asked to sign, which is a concrete integrity defect.

## Fix Requirement
Preserve the parsed fragment when rebuilding the signed URL by appending `#` plus `parsed.fragment()` when present.

## Patch Rationale
The patch should be minimal and preserve existing signing behavior. Only the final URL reconstruction needs adjustment: after the signed base URL and query string are built, append the original fragment unchanged if one exists. This restores round-trip fidelity without affecting token generation or query ordering.

## Residual Risk
None

## Patch
Patch file: `002-fragment-identifiers-are-silently-discarded.patch`

```diff
diff --git a/rust/src/lib.rs b/rust/src/lib.rs
--- a/rust/src/lib.rs
+++ b/rust/src/lib.rs
@@
-    Ok(format!(
-        "{}://{}{}{}{}",
-        parsed.scheme(),
-        parsed.host_str().ok_or(SecureTokenError::BadUrl)?,
-        base,
-        tail,
-        parsed.path()
-    ))
+    let fragment = parsed
+        .fragment()
+        .map(|fragment| format!("#{}", fragment))
+        .unwrap_or_default();
+
+    Ok(format!(
+        "{}://{}{}{}{}{}",
+        parsed.scheme(),
+        parsed.host_str().ok_or(SecureTokenError::BadUrl)?,
+        base,
+        tail,
+        parsed.path(),
+        fragment
+    ))
```