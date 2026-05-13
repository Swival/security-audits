# Missing Parameter Segment Panics Route Matching

## Classification

Denial of service, medium severity.

## Affected Locations

`src/runtime/bake/FrameworkRouter.rs:316`

## Summary

`EncodedPattern::matches` can panic while matching a dynamic route when the request path ends immediately after a preceding static segment. For a route like `/foo/[id]`, a request to `/foo` advances the matcher index beyond `path.len()` and then slices `&path[i..end]` with an invalid range.

## Provenance

Verified finding from Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The router contains a dynamic route with a static segment before a parameter, such as `/foo/[id]`.
- No static route exists for the requested static prefix, such as `/foo`.
- A remote HTTP client requests the static prefix path.

## Proof

`DevServer` handles incoming requests by calling `dev.router.match_slow(req.url(), &mut params)` at `src/runtime/bake/DevServer.rs:5081`.

`FrameworkRouter::match_slow` first misses `static_routes.get(path)`, then iterates `dynamic_routes` and calls `pattern.matches(path, params)` at `src/runtime/bake/FrameworkRouter.rs:1339`.

For route `/foo/[id]` and request `/foo`:

- `EncodedPattern::matches` starts with `i = 1`.
- The `Text("foo")` arm accepts the path because `path.len() == i + expect.len()`.
- It then advances `i` by `1 + expect.len()`, making `i = 5` while `path.len() = 4`.
- The following `Param` arm computes `end = path.len()` because no slash exists at or after `i`.
- It then builds `&path[i..end]`, producing `&path[5..4]`.
- Rust panics on this invalid slice range.

The workspace profile aborts on panic according to `Cargo.toml:151` and `Cargo.toml:154`, so the request can terminate the affected worker/process.

## Why This Is A Real Bug

The route matcher treats a path ending immediately after a static segment as a valid prefix for the next parameter, but it does not ensure the parameter segment exists before slicing. The invalid slice is reachable from remote HTTP requests through normal dev-server routing, and panic-abort behavior turns this into denial of service.

## Fix Requirement

Before slicing a parameter value, reject matches where the current matcher index is greater than the request path length.

## Patch Rationale

The patch adds a bounds check at the start of the `Part::Param` arm:

```rust
if i > path.len() {
    return false;
}
```

This preserves valid matches where `i <= path.len()` and rejects impossible parameter captures before computing or slicing the parameter range. It directly prevents the `&path[5..4]` panic case.

## Residual Risk

None

## Patch

```diff
diff --git a/src/runtime/bake/FrameworkRouter.rs b/src/runtime/bake/FrameworkRouter.rs
index 9cd12a1a4b..aa90884789 100644
--- a/src/runtime/bake/FrameworkRouter.rs
+++ b/src/runtime/bake/FrameworkRouter.rs
@@ -358,6 +358,9 @@ impl EncodedPattern {
                     i += 1 + expect.len();
                 }
                 Part::Param(name) => {
+                    if i > path.len() {
+                        return false;
+                    }
                     let end = strings::index_of_char_pos(path, b'/', i).unwrap_or(path.len());
                     // Check if we're about to exceed the maximum number of parameters
                     if param_num >= MatchedParams::MAX_COUNT {
```