# Stale Walk Path Permits Outside-Root Deletion

## Classification

Path traversal / time-of-check-to-time-of-use filesystem race.

Severity: medium.

Confidence: certain.

## Affected Locations

`crates/nono/src/undo/snapshot.rs:318`

## Summary

`restore_to` collected live paths with `walk_current`, then deleted paths absent from the manifest using `fs::remove_file(path)` without revalidating the live filesystem target immediately before deletion. Because path resolution occurs at `remove_file` time, an attacker able to mutate tracked directory contents between the walk and deletion could replace a walked parent directory with a symlink to an outside directory and cause deletion outside the tracked root.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

The finding was reproduced and patched.

## Preconditions

- Restore runs on attacker-controlled tracked directory contents.
- The attacker can mutate the tracked filesystem between `walk_current` and the stale-file deletion loop.
- Restore has filesystem privileges sufficient to delete the outside target.

## Proof

The reproduced scenario is:

1. `walk_current` observes a stale path such as `tracked/subdir/stale`.
2. Before the deletion loop executes, the attacker replaces `tracked/subdir` with a symlink to an attacker-chosen outside directory.
3. `restore_to` reaches the stale-file cleanup path because `tracked/subdir/stale` is present in `current_files` but absent from the manifest.
4. The vulnerable call `fs::remove_file(tracked/subdir/stale)` resolves the symlinked parent at call time.
5. The operation can unlink `outside/stale` instead of a file under the tracked root.

Relevant code behavior:

- `crates/nono/src/undo/snapshot.rs:248` collects `current_files` before restore/delete work.
- `crates/nono/src/undo/snapshot.rs:253` validates only manifest restore write targets.
- `crates/nono/src/undo/snapshot.rs:318` deleted stale `current_files` paths directly with `fs::remove_file(path)`.
- `crates/nono/src/undo/snapshot.rs:651` walks with `follow_links(false)`, which avoids initial symlink traversal but does not protect against later parent-directory replacement.

## Why This Is A Real Bug

The vulnerable path was not a merely lexical traversal in a manifest. It was a live filesystem race: the path was safe when walked, but could resolve differently by the time `remove_file` executed. `walkdir` with `follow_links(false)` only constrains the initial walk. It does not bind path components for later operations, and `fs::remove_file` follows symlinked parent components during normal path resolution.

The existing restore write path already recognized this class of issue by using `validate_restore_target` before writes. The stale deletion path lacked the same check, creating an inconsistent safety boundary.

## Fix Requirement

Deletion targets must be revalidated immediately before `fs::remove_file`.

The validation must reject symlinked tracked roots and symlinked parent directory components so a stale lexical path cannot be redirected outside the tracked root at deletion time.

## Patch Rationale

The patch adds:

```rust
self.validate_restore_target(path)?;
```

immediately before stale-file deletion.

This reuses the existing live-path validation logic already used for restore writes. It selects the applicable tracked root, rejects symlinked tracked paths, walks parent components with `symlink_metadata`, and refuses symlinked or non-directory parents. If an attacker swaps a walked parent directory to a symlink before deletion, validation fails before `remove_file` is reached.

## Residual Risk

`validate_restore_target` itself walks parent components with path-based
`fs::symlink_metadata`, so a narrow race window between validation and
`fs::remove_file` remains. The patch closes the wide window opened by
`walk_current` but does not provide the same `openat`-based guarantee used
for restore writes in finding 029. A follow-up that performs unlink with
`unlinkat` relative to a validated directory file descriptor would close
the residual window.

## Patch

```diff
diff --git a/crates/nono/src/undo/snapshot.rs b/crates/nono/src/undo/snapshot.rs
index 5bf3773..d3ca875 100644
--- a/crates/nono/src/undo/snapshot.rs
+++ b/crates/nono/src/undo/snapshot.rs
@@ -318,6 +318,7 @@ impl SnapshotManager {
         // Delete files not in the manifest (created during session)
         for path in current_files.keys() {
             if !manifest.files.contains_key(path) {
+                self.validate_restore_target(path)?;
                 if let Err(e) = fs::remove_file(path) {
                     tracing::warn!("Failed to remove {}: {}", path.display(), e);
                 } else {
```