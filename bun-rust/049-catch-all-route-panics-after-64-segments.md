# catch-all route panics after 64 segments

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`src/runtime/bake/FrameworkRouter.rs:338`

## Summary

A remote HTTP request can panic the route matching path when the application has a catch-all or optional catch-all dynamic route and the requested URL contains more than 64 nonempty captured segments. The catch-all matcher appends every remaining segment to `MatchedParams`; after 64 entries it calls `Output::panic`, which propagates to Rust `panic!`.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- The application has a catch-all or optional catch-all dynamic route.
- A remote client can request a URL whose prefix matches that route.
- The catch-all suffix contains more than 64 nonempty path segments.

## Proof

- Request routing passes the URL path into `dev.router.match_slow(...)` at `src/runtime/bake/DevServer.rs:5081`.
- `FrameworkRouter::match_slow` checks dynamic route patterns and calls `pattern.matches(path, params)` at `src/runtime/bake/FrameworkRouter.rs:1344`.
- `EncodedPattern::matches` handles `Part::CatchAllOptional` and `Part::CatchAll` by iterating all remaining nonempty path segments and appending each segment to `MatchedParams`.
- `MatchedParams::MAX_COUNT` is 64 at `src/runtime/bake/FrameworkRouter.rs:1299`.
- When the 65th segment is processed, the matcher checks `param_num >= MatchedParams::MAX_COUNT` and calls `Output::panic(...)`.
- `Output::panic` ultimately invokes Rust `panic!` at `src/bun_core/output.rs:1046`.

## Why This Is A Real Bug

The scanner finding was reproduced. Route scanning only rejects route patterns with more than 64 route parameters; it does not reject a catch-all request containing more than 64 captured segments. Because catch-all matching converts each captured segment into a `MatchedParamEntry`, an attacker-controlled URL can deterministically exceed the fixed parameter capacity and panic the request handling path.

## Fix Requirement

The router must not panic on attacker-controlled path length. If a catch-all match would exceed `MatchedParams::MAX_COUNT`, matching should fail or return a controlled error instead of calling `Output::panic`.

## Patch Rationale

The patch changes the catch-all overflow branch from `Output::panic(...)` to `return false`. This treats overlong catch-all URLs as non-matches, preserves the fixed-size `MatchedParams` invariant, and prevents a remote request from triggering a process-level panic during route matching.

## Residual Risk

None

## Patch

```diff
diff --git a/src/runtime/bake/FrameworkRouter.rs b/src/runtime/bake/FrameworkRouter.rs
index 9cd12a1a4b..362588cbc5 100644
--- a/src/runtime/bake/FrameworkRouter.rs
+++ b/src/runtime/bake/FrameworkRouter.rs
@@ -384,14 +384,9 @@ impl EncodedPattern {
                             let segment_end = strings::index_of_char_pos(path, b'/', segment_start)
                                 .unwrap_or(path.len());
                             if segment_start < segment_end {
-                                // Check if we're about to exceed the maximum number of parameters
+                                // Treat overlong catch-all paths as non-matches instead of panicking.
                                 if param_num >= MatchedParams::MAX_COUNT {
-                                    // TODO: ideally we should throw a nice user message
-                                    Output::panic(format_args!(
-                                        "Route pattern matched more than {} parameters. Path: {}",
-                                        MatchedParams::MAX_COUNT,
-                                        bstr::BStr::new(path)
-                                    ));
+                                    return false;
                                 }
                                 params.params.resize(param_num + 1).unwrap();
                                 params.params.slice()[param_num] = MatchedParamEntry {
```