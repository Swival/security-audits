# Unsigned Tag Name Executes In Privileged Shell

## Classification

Command execution. Severity: high. Confidence: certain.

## Affected Locations

`.github/workflows/release.yml:108`

## Summary

The release workflow accepted tag names matching `v*.*.*` and embedded `${{ steps.vars.outputs.version_tag }}` directly into a privileged Bash `run` block. GitHub Actions expression interpolation occurs before shell parsing, so shell metacharacters in a crafted tag name, such as command substitution, were interpreted by Bash before `git verify-tag` could reject the unsigned tag.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

An attacker can push a matching tag to the repository.

## Proof

A repository collaborator able to create tags could push a crafted `v*.*.*` tag containing shell metacharacters. The workflow copies the raw tag from `GITHUB_REF` into `steps.vars.outputs.version_tag`, then uses that output directly inside the `Validate commits and tag signatures` Bash script.

The vulnerable operations were:

- `echo "Verifying the tag: ${{ steps.vars.outputs.version_tag }}"`
- `git verify-tag -v "${{ steps.vars.outputs.version_tag }}"`

Because GitHub substitutes `${{ ... }}` before Bash parses the script, a tag such as `v1.2.3$(touch${IFS}pwn)` is parsed as shell syntax. The reproducer confirmed this behavior locally: the substituted script line created the file before any `git verify-tag` call could reject the tag.

The first vulnerable `echo` executes before signature verification, so the command execution does not depend on the tag being signed.

## Why This Is A Real Bug

The workflow is triggered by pushed tags matching `v*.*.*`, which can still contain shell metacharacters. The vulnerable job grants elevated permissions:

- `contents: write`
- `pull-requests: write`
- `issues: write`

`actions/checkout` also configures authenticated Git access. As a result, injected shell commands run in a privileged release job context and can perform repository-write operations before the unsigned tag is rejected.

## Fix Requirement

Pass the tag value through the step environment and reference it only as a quoted shell variable inside the Bash script.

## Patch Rationale

The patch moves the interpolated GitHub Actions expression into the `env` block:

```yaml
version_tag: ${{ steps.vars.outputs.version_tag }}
```

The Bash script then uses `"$version_tag"` instead of embedding `${{ steps.vars.outputs.version_tag }}` directly in executable shell code. This prevents shell metacharacters in the tag name from being introduced into the script source before Bash parsing. Quoting `"$version_tag"` preserves the tag as data for `echo`, `git verify-tag`, and `git push --delete`.

## Residual Risk

None

## Patch

```diff
diff --git a/.github/workflows/release.yml b/.github/workflows/release.yml
index 2cddde61..bc92a5d2 100644
--- a/.github/workflows/release.yml
+++ b/.github/workflows/release.yml
@@ -80,6 +80,7 @@ jobs:
         id: verify
         env:
           signing_keys: ${{ secrets.SIGNING_KEYS }}
+          version_tag: ${{ steps.vars.outputs.version_tag }}
         run: |
           # Read the string into an array, splitting by IFS
           IFS=";" read -ra keys_collection <<< "$signing_keys"
@@ -104,17 +105,17 @@ jobs:
 
           git config set --global gpg.ssh.allowedSignersFile "${{ runner.temp }}/allowed_signers"
 
-          echo "Verifying the tag: ${{ steps.vars.outputs.version_tag }}"
+          echo "Verifying the tag: $version_tag"
           
           # Verify the tag is signed
-          if ! git verify-tag -v "${{ steps.vars.outputs.version_tag }}" 2>&1; then
+          if ! git verify-tag -v "$version_tag" 2>&1; then
             echo "❌ Tag verification failed!"
             echo "passed=false" >> $GITHUB_OUTPUT
-            git push --delete origin "${{ steps.vars.outputs.version_tag }}"
+            git push --delete origin "$version_tag"
             exit 1
           fi
           # Run it again to capture the output
-          git verify-tag -v "${{ steps.vars.outputs.version_tag }}" 2>&1 | tee /tmp/verify-output.txt;
+          git verify-tag -v "$version_tag" 2>&1 | tee /tmp/verify-output.txt;
 
           # SSH verification output typically includes the key fingerprint
           # Use GNU grep with Perl regex for cleaner extraction (Linux environment)
@@ -134,7 +135,7 @@ jobs:
             echo "Somehow could not extract SSH key fingerprint from git verify-tag output"
             echo "Cancelling flow and deleting tag"
             echo "passed=false" >> $GITHUB_OUTPUT
-            git push --delete origin "${{ steps.vars.outputs.version_tag }}"
+            git push --delete origin "$version_tag"
             exit 1
           fi

```