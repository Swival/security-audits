# Malformed Optional Catchall Route Panics Validation

## Classification

denial of service, medium severity, certain confidence

## Affected Locations

- `src/router/lib.rs:1129`
- `src/router/lib.rs:1896`

## Summary

A malformed optional catchall route filename such as `[[...slug].js` can panic route validation during `RouteLoader` scanning. The parser recognizes optional catchall syntax, consumes the only closing bracket, increments its index past the end of the input, then reads `input[i as usize]` without a bounds check while expecting the second closing bracket. Rust slice indexing panics, aborting route loading.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- An attacker can create route files scanned by `RouteLoader`.
- The crafted route file has an allowed extension, for example `[[...slug].js`.
- The route file is not excluded by dotfile or banned-directory filtering.

## Proof

The finding was reproduced from source inspection.

- `RouteLoader::load` accepts a file named `[[...slug].js` because `.js` passes configured extension filtering.
- `RouteLoader::load` calls `Route::parse(...)` at `src/router/lib.rs:883`.
- `Route::parse` strips `.js`, derives the route name `/[[...slug]`, and calls `Pattern::validate(&name[1..], log)` at `src/router/lib.rs:1109`.
- `Pattern::validate` receives `[[...slug]`.
- `Pattern::init_maybe_hash` detects `[[...` as optional catchall syntax, scans to the only `]`, increments `i`, and then evaluates `input[i as usize]` while checking for the required second `]`.
- For `[[...slug]`, `i` is past `end`, so `input[i as usize]` panics.

## Why This Is A Real Bug

This is not just invalid route syntax. Invalid route syntax is expected to be reported through `PatternParseError` and logged as a validation error. Instead, this malformed filename reaches an unchecked slice index and triggers a Rust panic. Because route loading does not catch that panic, a lower-privileged local user who controls route filenames under a scanned routes directory can crash or abort route loading, causing denial of service.

## Fix Requirement

Before reading the second closing bracket for an optional catchall route, the parser must verify that `i` is still within bounds. If the bracket is missing, validation must return `PatternParseError::PatternMissingClosingBracket` instead of indexing past the slice.

## Patch Rationale

The patch changes the optional catchall closing-bracket check from an unconditional indexed read to a guarded condition:

```rust
if i > end || input[i as usize] != b']' {
    return Err(PatternParseError::PatternMissingClosingBracket);
}
```

This preserves existing behavior for valid `[[...param]]` routes, preserves the existing error type for missing closing brackets, and prevents the out-of-bounds panic for malformed `[[...param]` input.

## Residual Risk

None

## Patch

```diff
diff --git a/src/router/lib.rs b/src/router/lib.rs
index 2d5fc1f685..187540ffe8 100644
--- a/src/router/lib.rs
+++ b/src/router/lib.rs
@@ -1894,7 +1894,7 @@ pub mod pattern {
                         i += 1;
 
                         if matches!(tag, Tag::OptionalCatchAll) {
-                            if input[i as usize] != b']' {
+                            if i > end || input[i as usize] != b']' {
                                 return Err(PatternParseError::PatternMissingClosingBracket);
                             }
                             i += 1;
```