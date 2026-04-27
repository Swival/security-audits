# Mutable Remote Helper Executed

## Classification

Trust-boundary violation, medium severity.

## Affected Locations

`library/portable-simd/subtree-sync.sh:21`

## Summary

`library/portable-simd/subtree-sync.sh` downloaded `git-subtree.sh` from a mutable GitHub branch when the local helper was missing, marked it executable, and later executed it. Because the downloaded code was not pinned to an immutable commit and was not verified by checksum or signature, untrusted remote content could execute locally with the invoking user's privileges.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `library/portable-simd/git-subtree.sh` is absent.
- The user runs `library/portable-simd/subtree-sync.sh` from the git repository root.
- Local `HEAD` equals `origin/master`.
- `$2` points to a repository where `git fetch origin` succeeds.
- Network or remote content from the helper URL is untrusted.

## Proof

When `library/portable-simd/git-subtree.sh` is missing, execution reaches:

```bash
curl -sS https://raw.githubusercontent.com/bjorn3/git/tqc-subtree-portable/contrib/subtree/git-subtree.sh -o library/portable-simd/git-subtree.sh
chmod +x library/portable-simd/git-subtree.sh
```

The URL references `tqc-subtree-portable`, a mutable branch/path on `raw.githubusercontent.com`, not an immutable commit. The script performs no checksum or signature verification before making the downloaded file executable.

The downloaded helper is then executed in both supported modes:

```bash
library/portable-simd/git-subtree.sh push -P library/portable-simd $2 $upstream
```

```bash
library/portable-simd/git-subtree.sh pull -P library/portable-simd $2 origin/master
```

Thus, for either `push` or `pull`, remote-controlled helper contents can run locally after the missing-file check.

## Why This Is A Real Bug

This crosses a trust boundary by converting unauthenticated, mutable network content into executable local code. The branch-backed GitHub raw URL can change over time, and the script does not bind the downloaded helper to an expected digest, signature, or vendored copy. Under the reproduced preconditions, any code served from that URL is executed by the script with the user's privileges.

## Fix Requirement

The script must not download and execute mutable remote code without verification. Acceptable fixes include:

- vendor `git-subtree.sh` in the repository and require that local copy, or
- download from immutable content and verify a pinned checksum before `chmod` or execution.

## Patch Rationale

The patch removes the insecure download-and-execute path. If `library/portable-simd/git-subtree.sh` is missing, the script now fails closed with an explicit error:

```bash
echo "library/portable-simd/git-subtree.sh is missing; install the vendored helper before running this script" >&2
exit 1
```

This preserves the existing behavior when the helper is already present, while preventing unverified remote content from being fetched, marked executable, and run.

## Residual Risk

None

## Patch

```diff
diff --git a/library/portable-simd/subtree-sync.sh b/library/portable-simd/subtree-sync.sh
index 18360077623..856258f574d 100755
--- a/library/portable-simd/subtree-sync.sh
+++ b/library/portable-simd/subtree-sync.sh
@@ -18,8 +18,8 @@ if [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/master)" ]; then
 fi
 
 if [ ! -f library/portable-simd/git-subtree.sh ]; then
-    curl -sS https://raw.githubusercontent.com/bjorn3/git/tqc-subtree-portable/contrib/subtree/git-subtree.sh -o library/portable-simd/git-subtree.sh
-    chmod +x library/portable-simd/git-subtree.sh
+    echo "library/portable-simd/git-subtree.sh is missing; install the vendored helper before running this script" >&2
+    exit 1
 fi
 
 today=$(date +%Y-%m-%d)
```