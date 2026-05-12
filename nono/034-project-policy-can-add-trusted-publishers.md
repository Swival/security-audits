# Project Policy Can Add Trusted Publishers

## Classification

High severity policy bypass.

## Affected Locations

`crates/nono/src/trust/policy.rs:114`

## Summary

`merge_policies` unioned publishers from all policy levels, including attacker-controlled project policy. This let a project repository add a new trusted publisher and have attacker-signed instruction files treated as verified after policy merge.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Victim merges an attacker-controlled project `trust-policy.json` with an existing trusted policy.

## Proof

The vulnerable merge logic iterated over every policy and inserted any unseen publisher name into `merged_publishers`. A project policy could therefore add a publisher identity controlled by the repository author.

After merge, file evaluation used the resulting publisher set:

- `evaluate_file` called `policy.matching_publishers(identity)`.
- If the attacker-controlled signer identity matched the project-added publisher, the result became `VerificationOutcome::Verified`.

The reproducer confirmed that policy bundle verification did not authorize the project policy signer against the user policy before this merge. Keyless policy verification used default Sigstore verification without identity pinning at `crates/nono-cli/src/trust_scan.rs:140` and `crates/nono-cli/src/trust_scan.rs:240`.

Impact: a malicious repository author could add a project policy trusting their CI/keyless identity, include a matching signed instruction file bundle, and have that instruction file treated as verified under the victim's effective policy.

## Why This Is A Real Bug

The policy documentation states that project-level policy cannot weaken user-level or embedded policy. Adding a new trusted publisher is a trust expansion, not a restriction. Because publisher matching directly controls `VerificationOutcome::Verified`, unioning project publishers bypassed the intended signer authorization boundary.

## Fix Requirement

Project-level policy must not add trust roots. Publisher definitions must be accepted only from an already trusted anchor policy unless an explicit authorization mechanism exists for project publisher additions.

## Patch Rationale

The patch changes publisher merge semantics so publishers are copied only from the first trusted anchor policy. Later policies still contribute include patterns, file paths, blocklist entries, blocked publishers, and stricter enforcement, but they cannot add new publishers.

This preserves useful project-level narrowing and blocking behavior while preventing attacker-controlled project policy from expanding the trusted signer set.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono/src/trust/policy.rs b/crates/nono/src/trust/policy.rs
index e4d85a9..9eb8491 100644
--- a/crates/nono/src/trust/policy.rs
+++ b/crates/nono/src/trust/policy.rs
@@ -7,7 +7,7 @@
 //! # Policy Composition
 //!
 //! Multiple `trust-policy.json` files are merged with additive-only semantics:
-//! - Publishers: union (all publishers from all levels)
+//! - Publishers: only from the trusted anchor policy
 //! - Blocklist digests: union (all blocked digests from all levels)
 //! - Blocked publishers: union
 //! - Include patterns: union (all patterns from all levels)
@@ -52,8 +52,9 @@ pub fn load_policy_from_file<P: AsRef<Path>>(path: P) -> Result<TrustPolicy> {
 ///
 /// Policies are merged in order (first = lowest priority, last = highest).
 /// All merging is additive-only:
-/// - Publishers, blocklist entries, blocked publishers, and include
-///   patterns are unioned (deduplicated by identity)
+/// - Publishers come only from the first trusted anchor policy
+/// - Blocklist entries, blocked publishers, and include patterns are unioned
+///   (deduplicated by identity)
 /// - Enforcement uses the strictest level across all policies
 ///
 /// # Errors
@@ -87,7 +88,7 @@ pub fn merge_policies(policies: &[TrustPolicy]) -> Result<TrustPolicy> {
 
     let mut strictest_enforcement = Enforcement::Audit;
 
-    for policy in policies {
+    for (policy_index, policy) in policies.iter().enumerate() {
         // Merge include patterns (deduplicate by pattern string)
         for pattern in &policy.includes {
             if seen_patterns.insert(pattern.clone()) {
@@ -102,16 +103,15 @@ pub fn merge_policies(policies: &[TrustPolicy]) -> Result<TrustPolicy> {
             }
         }
 
-        // Merge publishers (deduplicate by name, first-occurrence wins).
-        // Callers pass policies in precedence order (user-level first),
-        // so user publishers take priority over project publishers.
+        // Merge publishers from the trusted anchor policy only. Later policies
+        // may narrow scope with includes/blocklists but must not add trust roots.
         for publisher in &policy.publishers {
             if !seen_publisher_names.insert(publisher.name.clone()) {
                 tracing::debug!(
-                    "trust policy merge: publisher '{}' appears in multiple policies, using the user-level definition for verification",
+                    "trust policy merge: publisher '{}' appears in multiple policies, using the trusted definition for verification",
                     publisher.name
                 );
-            } else {
+            } else if policy_index == 0 {
                 merged_publishers.push(publisher.clone());
             }
         }
@@ -555,7 +555,7 @@ mod tests {
     }
 
     #[test]
-    fn merge_unions_publishers() {
+    fn merge_ignores_later_publisher_additions() {
         let p1 = make_policy(
             Enforcement::Audit,
             vec![keyed_publisher("dev", "key1")],
@@ -567,7 +567,8 @@ mod tests {
             vec![],
         );
         let merged = merge_policies(&[p1, p2]).unwrap();
-        assert_eq!(merged.publishers.len(), 2);
+        assert_eq!(merged.publishers.len(), 1);
+        assert_eq!(merged.publishers[0].name, "dev");
     }
 
     #[test]
```