# Duplicate Credentials Survive Cross-Origin Redirect Stripping

## Classification

Information disclosure, medium severity, certain confidence.

## Affected Locations

`src/http/lib.rs:4619`

## Summary

Cross-origin redirect handling removed only the first matching sensitive request header for each protected name. If a request contained duplicate `Authorization`, `Proxy-Authorization`, or `Cookie` headers, one duplicate survived the redirect scrub and was serialized into the follow-up request to the redirected origin.

## Provenance

Verified and reproduced from Swival.dev Security Scanner findings: https://swival.dev

## Preconditions

- Client follows redirects.
- Request contains duplicate sensitive headers.
- Redirect response is cross-origin and uses a followed redirect status: `301`, `302`, `303`, `307`, or `308`.

## Proof

The redirect path in `handle_response_metadata` detects cross-origin redirects and iterates the sensitive header names `Authorization`, `Proxy-Authorization`, and `Cookie`.

Before the patch, each sensitive header name was removed by:

```rust
.position(...)
ordered_remove(i)
```

That removes only the first matching entry. Duplicate entries are otherwise preserved: `HeaderBuilder::append` appends without deduplication, `build_request` copies every remaining user header into the request header buffer, and request serialization iterates all request headers onto the wire.

A practical trigger is a request with two `Authorization` headers followed by a cross-origin `302`. The first `Authorization` is stripped, the second remains in `self.header_entries`, and the redirected request sends it to the attacker-controlled `Location`.

## Why This Is A Real Bug

The code explicitly implements Fetch redirect credential stripping for cross-origin redirects, but its removal primitive only deletes one occurrence per header name. HTTP header lists can contain duplicates in this implementation, and later request construction serializes all remaining entries. Therefore the intended security invariant, "cross-origin redirects do not forward sensitive headers," is violated when duplicates exist.

## Fix Requirement

Remove every matching sensitive header entry during cross-origin redirect stripping, not just the first matching entry.

## Patch Rationale

The patch replaces the single `position(...)` lookup with an index-based loop over `self.header_entries`. When a matching sensitive header is found, `ordered_remove(i)` deletes it and the loop keeps the same index so the next shifted entry is inspected. When no match is found, the index advances. This removes all duplicates without skipping adjacent matches.

## Residual Risk

None

## Patch

```diff
diff --git a/src/http/lib.rs b/src/http/lib.rs
index f083ec93da..aea074d95e 100644
--- a/src/http/lib.rs
+++ b/src/http/lib.rs
@@ -4617,17 +4617,16 @@ impl<'a> HTTPClient<'a> {
                                 },
                             ];
                             for to_remove in headers_to_remove.iter() {
-                                let found =
-                                    self.header_entries
-                                        .items_name()
-                                        .iter()
-                                        .position(|name_ptr| {
-                                            let name = self.header_str(*name_ptr);
-                                            name.len() == to_remove.name.len()
-                                                && hash_header_name(name) == to_remove.hash
-                                        });
-                                if let Some(i) = found {
-                                    self.header_entries.ordered_remove(i);
+                                let mut i = 0;
+                                while i < self.header_entries.len() {
+                                    let name = self.header_str(self.header_entries.items_name()[i]);
+                                    if name.len() == to_remove.name.len()
+                                        && hash_header_name(name) == to_remove.hash
+                                    {
+                                        let _ = self.header_entries.ordered_remove(i);
+                                    } else {
+                                        i += 1;
+                                    }
                                 }
                             }
                         }
```