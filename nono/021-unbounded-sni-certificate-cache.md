# Unbounded SNI Certificate Cache

## Classification

Denial of service, medium severity.

## Affected Locations

`crates/nono-proxy/src/tls_intercept/cert_cache.rs:90`

## Summary

The TLS interception certificate cache accepted attacker-controlled SNI hostnames and inserted one freshly minted certificate per unique hostname into a session `HashMap` without any size bound. A sandboxed child process able to open proxied TLS connections could present many unique plausible DNS SNI values, forcing repeated P-256 key generation and certificate signing while growing proxy memory until the session ended.

## Provenance

Verified from the provided source, reproducer summary, and patch.

Originally reported by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- TLS interception is enabled.
- A sandboxed child can open proxied TLS connections through the proxy.
- The child can control or vary the TLS SNI value in intercepted handshakes.

## Proof

The reproduced path is:

- `server.rs:702` validates proxy auth.
- `server.rs:746` calls `handle_intercept_connect`.
- `handle.rs:65` builds a rustls acceptor using the shared `CertCache`.
- rustls invokes `CertCache::resolve` during each intercepted handshake.
- `crates/nono-proxy/src/tls_intercept/cert_cache.rs:113` reads attacker-controlled SNI via `client_hello.server_name()`.
- `crates/nono-proxy/src/tls_intercept/cert_cache.rs:114` calls `get_or_mint(hostname)`.
- `get_or_mint` checks only exact cache hits, then mints on misses and inserts `hostname.to_string()` into `cache`.
- `mint_leaf` generates a fresh ECDSA P-256 key pair and signs a new leaf certificate for every unique accepted hostname.
- The file comments explicitly stated there was no LRU eviction and assumed the cache was naturally bounded by the per-session host set.

Therefore, many unique alphabetic DNS-like SNI names cause unbounded cache growth plus repeated expensive certificate minting.

## Why This Is A Real Bug

The SNI hostname is attacker-controlled within the stated threat model. Existing validation rejects empty, malformed, and IP-literal names, but still permits an effectively large set of plausible DNS names such as `a1.example`, `a2.example`, and so on. Each accepted unique value misses the exact-key cache lookup, triggers CPU-expensive certificate generation, and stores a new `Arc<CertifiedKey>` until proxy shutdown. This creates a practical CPU and memory exhaustion path that can deny further intercepted connections.

## Fix Requirement

The certificate cache must enforce a per-session upper bound. When the bound is reached, the proxy must either evict old entries or reject new unique SNI hostnames without minting and storing additional certificates.

## Patch Rationale

The patch adds `MAX_CERT_CACHE_ENTRIES: usize = 128` and checks `cache.len()` before minting a certificate for a cache miss.

This is sufficient because:

- Existing cache hits still return the previously minted certificate.
- New unique hostnames are rejected once the per-session cap is reached.
- Rejected entries do not invoke `mint_leaf`, avoiding further P-256 key generation and signing.
- Rejected entries are not inserted into the `HashMap`, bounding retained memory.
- The resolver already converts minting failures into `None`, causing rustls to fail the handshake as documented.

The documentation was also updated to remove the incorrect claim that the cache is naturally bounded and to describe the hard per-session entry limit.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono-proxy/src/tls_intercept/cert_cache.rs b/crates/nono-proxy/src/tls_intercept/cert_cache.rs
index 837b99a..e8b7bd0 100644
--- a/crates/nono-proxy/src/tls_intercept/cert_cache.rs
+++ b/crates/nono-proxy/src/tls_intercept/cert_cache.rs
@@ -8,9 +8,9 @@
 //! ## Why no LRU eviction
 //!
 //! Typical agent workloads hit a handful of distinct hosts (`api.openai.com`,
-//! `api.anthropic.com`, `api.github.com`, …). The cache is naturally bounded
-//! by the per-session host set and is dropped — along with the CA — when the
-//! proxy shuts down. An LRU policy would add complexity without payoff.
+//! `api.anthropic.com`, `api.github.com`, …). The cache has a hard per-session
+//! entry limit and is dropped — along with the CA — when the proxy shuts down.
+//! An LRU policy would add complexity without payoff.
 //!
 //! ## Failure mode
 //!
@@ -39,6 +39,7 @@ use tracing::{debug, warn};
 /// stolen leaf becomes useless quickly; long enough that no plausible
 /// HTTP request will outlive it.
 const LEAF_VALIDITY: Duration = Duration::from_secs(60 * 60);
+const MAX_CERT_CACHE_ENTRIES: usize = 128;
 
 /// Per-hostname leaf certificate cache backed by the session's [`EphemeralCa`].
 pub struct CertCache {
@@ -85,6 +86,12 @@ impl CertCache {
         if let Some(existing) = cache.get(hostname) {
             return Ok(Arc::clone(existing));
         }
+        if cache.len() >= MAX_CERT_CACHE_ENTRIES {
+            return Err(ProxyError::Config(format!(
+                "tls_intercept cert cache limit exceeded ({})",
+                MAX_CERT_CACHE_ENTRIES
+            )));
+        }
         let minted = mint_leaf(self.ca.as_ref(), hostname)?;
         cache.insert(hostname.to_string(), Arc::clone(&minted));
         debug!("tls_intercept: minted leaf certificate for {}", hostname);
```