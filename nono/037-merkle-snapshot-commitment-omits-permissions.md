# Merkle Snapshot Commitment Omits Permissions

## Classification

High severity security control failure.

## Affected Locations

- `crates/nono/src/undo/merkle.rs:61`
- `crates/nono/src/undo/merkle.rs:114`

## Summary

The Merkle snapshot commitment did not include `FileState.permissions` in leaf hashes. As a result, two snapshot manifests with identical paths and content hashes but different permissions produced the same Merkle root. If that root is signed and used as a tamper-evident filesystem-state commitment, permission-only changes are not attested.

## Provenance

Verified and patched finding from Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A verifier relies on the signed Merkle root to attest filesystem state.
- The attacker can present or cause evaluation of a snapshot manifest differing only in `FileState.permissions`.
- Paths and content hashes remain unchanged.

## Proof

`crates/nono/src/undo/merkle.rs` defines the Merkle root as the value signed by a hardware key for tamper-evident proof of filesystem state.

Before the patch:

- `FileState` includes `permissions`, so permissions are part of captured snapshot state.
- `MerkleTree::from_manifest` sorted paths and called `compute_leaf_hash(path, &file_state.hash)`.
- `compute_leaf_hash` hashed only `0x00 || path_bytes || content_hash`.
- `FileState.permissions` was never included in the leaf.
- Therefore, manifests differing only by permissions, such as `0600 -> 0644` or adding executable bits, produced identical leaves, identical internal nodes, and the same root.

This was reproduced: permission-only snapshot differences shared the same Merkle root even though snapshot logic separately treats permission-only changes as state changes.

## Why This Is A Real Bug

The Merkle root is documented as committing to the entire filesystem state captured by a snapshot and as the value signed for tamper-evident proof. Permissions are security-relevant filesystem state: changing readability, writability, or executability can alter confidentiality, integrity, or execution behavior without changing file contents.

Because permissions were omitted, the signed commitment failed open for permission-only tampering. A verifier could accept a modified filesystem state as matching the signed snapshot.

## Fix Requirement

Include canonical file permissions in each Merkle leaf hash before signing or verifying the root.

The encoding must be deterministic across producer and verifier. The patch uses `permissions.to_be_bytes()` to serialize the `u32` permission value canonically.

## Patch Rationale

The patch changes leaf construction from:

```text
SHA-256(0x00 || canonical_path_bytes || file_content_hash)
```

to:

```text
SHA-256(0x00 || canonical_path_bytes || file_content_hash || permissions_be_u32)
```

This binds permissions into every leaf while preserving:

- Existing domain separation via `LEAF_PREFIX`.
- Existing path ordering and internal-node construction.
- Deterministic hashing across insertion order.
- Fixed-width permission serialization.

The added regression test confirms that two otherwise identical manifests with different permissions now produce different Merkle roots.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono/src/undo/merkle.rs b/crates/nono/src/undo/merkle.rs
index 29514f3..93bf9ab 100644
--- a/crates/nono/src/undo/merkle.rs
+++ b/crates/nono/src/undo/merkle.rs
@@ -2,7 +2,7 @@
 //!
 //! Computes a Merkle root that cryptographically commits to the entire
 //! filesystem state captured by a snapshot. The root is a single 32-byte
-//! value - any change to any file path or content changes the root.
+//! value - any change to any file path, content, or permissions changes the root.
 //!
 //! This root is the value that will be signed by a hardware key to provide
 //! tamper-evident proof of what an AI agent did or didn't modify.
@@ -24,8 +24,8 @@ const INTERNAL_PREFIX: u8 = 0x01;
 
 /// A Merkle tree computed over snapshot file hashes.
 ///
-/// Leaves are `SHA-256(0x00 || canonical_path_bytes || file_content_hash)` to bind
-/// path identity to content with domain separation. Internal nodes are
+/// Leaves are `SHA-256(0x00 || canonical_path_bytes || file_content_hash || permissions)` to bind
+/// path identity to content and permissions with domain separation. Internal nodes are
 /// `SHA-256(0x01 || left_child_hash || right_child_hash)`.
 ///
 /// File paths are sorted lexicographically to ensure deterministic tree
@@ -54,12 +54,12 @@ impl MerkleTree {
         let mut sorted_paths: Vec<&PathBuf> = files.keys().collect();
         sorted_paths.sort();
 
-        // Compute leaf hashes: SHA-256(path_bytes || content_hash)
+        // Compute leaf hashes: SHA-256(path_bytes || content_hash || permissions)
         let mut level: Vec<[u8; 32]> = sorted_paths
             .iter()
             .map(|path| {
                 let file_state = &files[*path];
-                compute_leaf_hash(path, &file_state.hash)
+                compute_leaf_hash(path, &file_state.hash, file_state.permissions)
             })
             .collect();
 
@@ -106,16 +106,17 @@ impl MerkleTree {
     }
 }
 
-/// Compute a leaf hash: SHA-256(0x00 || path_bytes || content_hash)
+/// Compute a leaf hash: SHA-256(0x00 || path_bytes || content_hash || permissions)
 ///
 /// The 0x00 prefix provides domain separation per RFC 6962,
 /// preventing second-preimage attacks where leaf and internal
 /// node hashes could be confused.
-fn compute_leaf_hash(path: &Path, content_hash: &ContentHash) -> [u8; 32] {
+fn compute_leaf_hash(path: &Path, content_hash: &ContentHash, permissions: u32) -> [u8; 32] {
     let mut hasher = Sha256::new();
     hasher.update([LEAF_PREFIX]);
     hasher.update(path_bytes(path));
     hasher.update(content_hash.as_bytes());
+    hasher.update(permissions.to_be_bytes());
     hasher.finalize().into()
 }
 
@@ -176,6 +177,7 @@ mod tests {
         let expected_leaf = compute_leaf_hash(
             Path::new("/a/file.txt"),
             &ContentHash::from_bytes([0x01; 32]),
+            0o644,
         );
         assert_eq!(*tree.root().as_bytes(), expected_leaf);
     }
@@ -208,6 +210,21 @@ mod tests {
         assert_ne!(tree1.root(), tree2.root());
     }
 
+    #[test]
+    fn root_changes_when_file_permissions_change() {
+        let mut files1 = HashMap::new();
+        files1.insert(PathBuf::from("/a.txt"), make_file_state(0x01));
+
+        let mut files2 = HashMap::new();
+        let mut file_state = make_file_state(0x01);
+        file_state.permissions = 0o755;
+        files2.insert(PathBuf::from("/a.txt"), file_state);
+
+        let tree1 = MerkleTree::from_manifest(&files1).expect("tree1");
+        let tree2 = MerkleTree::from_manifest(&files2).expect("tree2");
+        assert_ne!(tree1.root(), tree2.root());
+    }
+
     #[test]
     fn deterministic_regardless_of_insertion_order() {
         let mut files1 = HashMap::new();
```