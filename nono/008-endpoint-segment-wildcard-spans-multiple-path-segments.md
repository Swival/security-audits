# Endpoint Segment Wildcard Spans Multiple Path Segments

## Classification

security_control_failure, high severity, confidence certain

## Affected Locations

`crates/nono-proxy/src/config.rs:262`

## Summary

Endpoint path rules document `*` as matching exactly one `/`-separated path segment, but the implementation compiled rules with `globset::Glob::new` using default separator behavior. Under that behavior, `/api/*/data` matches both `/api/x/data` and `/api/x/y/data`, so a single-star endpoint rule can allow nested API paths that the documented policy should deny.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- A route defines non-empty `endpoint_rules`.
- At least one endpoint rule contains a single-star path segment, for example `GET /api/*/data`.
- A sandboxed child process can send requests through the configured proxy route.

## Proof

The reproduced runtime behavior confirms that `globset` default matching lets `*` span `/`:

- `Glob::new("/api/*/data")` matches `/api/x/data`.
- `Glob::new("/api/*/data")` also matches `/api/x/y/data`.

The allow decision is security-relevant and reachable:

- Reverse proxy endpoint filtering denies only when `route.endpoint_rules.is_allowed(&method, &upstream_path)` returns false at `crates/nono-proxy/src/reverse.rs:186`.
- TLS interception route selection also treats matching endpoint rules as eligible at `crates/nono-proxy/src/tls_intercept/handle.rs:186`.

Practical trigger:

- Policy: `GET /api/*/data`
- Request: `GET /api/a/b/data`
- Expected: denied, because `*` should match exactly one segment.
- Actual: allowed, because the compiled glob permits `*` to consume `a/b`.

## Why This Is A Real Bug

`CompiledEndpointRules::is_allowed` is the endpoint method-and-path access-control filter. When endpoint rules are configured, the intended behavior is default-deny unless a documented rule matches. Because the matcher is too broad, the filter deterministically returns allow for nested paths that the rule language says must not match. This is a fail-open access-control error, not a cosmetic mismatch.

## Fix Requirement

Compile endpoint path matchers with segment-aware separator semantics:

- `*` must not match `/`.
- `**` must continue to match across zero or more path segments.
- Production compiled rules and test-only helper matching must use the same semantics.

## Patch Rationale

The patch replaces `Glob::new(&rule.path)` with `GlobBuilder::new(&rule.path).literal_separator(true).build()` in both matcher construction paths.

With `literal_separator(true)`, `globset` treats `/` as a path separator for glob matching. This makes single-star wildcards segment-bounded while preserving double-star recursive matching semantics. Applying the same builder in `CompiledEndpointRules::compile` and the `#[cfg(test)]` `endpoint_allowed` helper keeps tests aligned with production behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono-proxy/src/config.rs b/crates/nono-proxy/src/config.rs
index 9f5f62d..e04e256 100644
--- a/crates/nono-proxy/src/config.rs
+++ b/crates/nono-proxy/src/config.rs
@@ -3,7 +3,7 @@
 //! Defines the configuration for the proxy server, including allowed hosts,
 //! credential routes, and external proxy settings.
 
-use globset::Glob;
+use globset::GlobBuilder;
 use serde::{Deserialize, Serialize};
 use std::net::IpAddr;
 use std::path::PathBuf;
@@ -284,7 +284,9 @@ impl CompiledEndpointRules {
     pub fn compile(rules: &[EndpointRule]) -> Result<Self, String> {
         let mut compiled = Vec::with_capacity(rules.len());
         for rule in rules {
-            let glob = Glob::new(&rule.path)
+            let glob = GlobBuilder::new(&rule.path)
+                .literal_separator(true)
+                .build()
                 .map_err(|e| format!("invalid endpoint path pattern '{}': {}", rule.path, e))?;
             compiled.push(CompiledRule {
                 method: rule.method.clone(),
@@ -335,7 +337,9 @@ fn endpoint_allowed(rules: &[EndpointRule], method: &str, path: &str) -> bool {
     let normalized = normalize_path(path);
     rules.iter().any(|r| {
         (r.method == "*" || r.method.eq_ignore_ascii_case(method))
-            && Glob::new(&r.path)
+            && GlobBuilder::new(&r.path)
+                .literal_separator(true)
+                .build()
                 .ok()
                 .map(|g| g.compile_matcher())
                 .is_some_and(|m| m.is_match(&normalized))
```