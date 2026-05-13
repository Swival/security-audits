# git committish is parsed as git-log option

## Classification

Command execution / argument injection. Severity: high. Confidence: certain.

## Affected Locations

`src/install/repository.rs:761`

## Summary

Attacker-controlled git dependency fragments are stored as `Repository.committish` and later passed to `git log` without an option terminator. A committish beginning with `-`, such as `--output=/path/to/file`, is interpreted by Git as a `git log` option instead of a revision. This allows an attacker-controlled dependency to overwrite an installer-writable file with Git log output.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- The installer resolves an attacker-controlled git dependency.
- The dependency includes a committish URL fragment.
- The fragment begins with a Git option accepted by `git log`, such as `--output=...`.
- The selected output path is writable by the installer process.

## Proof

`parse_append_git` stores the URL fragment after `#` directly into `Repository.committish` with no validation.

`Repository::find_commit` then builds the command as:

```text
git -C <path> log --format=%H -1 <committish>
```

Because there is no `--` separator before `<committish>`, Git parses a value like:

```text
--output=/installer/writable/file
```

as a `git log` option. The equivalent local command was confirmed against a bare repository:

```sh
git -C bare.git log --format=%H -1 --output=/path/to/victim
```

It exited successfully, produced no stdout, and overwrote `victim` with the commit hash plus newline. The file write occurs before later checkout failure from the empty resolved commit, so the side effect is practical.

## Why This Is A Real Bug

The committish is attacker-controlled package metadata, not a trusted CLI argument. Passing it to Git after options without `--` changes the command grammar: revision input can become option input. Git’s `--output=<file>` option performs a filesystem write, making this more than a resolution failure or denial of service. The reproduced command demonstrates the overwrite behavior directly.

## Fix Requirement

Ensure attacker-controlled committish values are always interpreted as revisions/pathspecs, not options. This can be done by passing `--` before the committish or by rejecting committish values beginning with `-`.

## Patch Rationale

The patch inserts `--` before `committish` in the `git log` invocation:

```text
git -C <path> log --format=%H -1 -- <committish>
```

Git treats arguments after `--` as non-options, so a fragment such as `--output=/path` is no longer parsed as a `git log` option. This preserves support for legitimate committish values while removing option injection.

## Residual Risk

None

## Patch

```diff
diff --git a/src/install/repository.rs b/src/install/repository.rs
index 5d518584e5..4ff74af1a2 100644
--- a/src/install/repository.rs
+++ b/src/install/repository.rs
@@ -758,13 +758,14 @@ impl RepositoryExt for Repository {
 
         let shared = SharedEnv::get(env);
 
-        let argv_with: [&[u8]; 7] = [
+        let argv_with: [&[u8]; 8] = [
             b"git",
             b"-C",
             path,
             b"log",
             b"--format=%H",
             b"-1",
+            b"--",
             committish,
         ];
         let argv_without: [&[u8]; 6] = [b"git", b"-C", path, b"log", b"--format=%H", b"-1"];
```