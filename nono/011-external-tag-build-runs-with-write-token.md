# External Tag Build Runs With Write Token

## Classification

High severity code execution / workflow token privilege exposure.

## Affected Locations

`scripts/downstream-workflows/bump-nono-go.yml:67`

## Summary

The `rebuild-libs` job builds an externally selected `always-further/nono` tag while the workflow has repository write permissions. Cargo build execution from that tag can run attacker-controlled build scripts, proc macros, or dependency build scripts on the GitHub Actions runner with access to write-scoped repository credentials.

## Provenance

Verified and patched from a Swival.dev Security Scanner finding: https://swival.dev

Confidence: certain.

## Preconditions

- An attacker can publish or control the selected tag in `always-further/nono`.
- The workflow is triggered through `repository_dispatch` or `workflow_dispatch` with `NONO_VERSION` selecting that tag.

## Proof

The workflow sets:

- `NONO_VERSION` from `github.event.client_payload.nono_version` or `github.event.inputs.nono_version`.
- Top-level permissions to `contents: write` and `pull-requests: write` before the patch.
- The `rebuild-libs` job checks out the repository with `actions/checkout`, which persists credentials by default.
- The same job clones `https://github.com/always-further/nono.git` at `$NONO_VERSION` into `/tmp/nono`.
- The same job then runs `cargo build` or `cross build` inside `/tmp/nono`.

Cargo may execute `build.rs`, proc macros, and dependency build scripts from the selected external tag. Therefore, a malicious `nono` tag can execute arbitrary commands on the runner before artifact upload, while repository write credentials are available in the job environment.

## Why This Is A Real Bug

This is not limited to compiling untrusted source. Rust build execution is code execution by design. Because the workflow previously granted write permissions globally, untrusted external code ran in a job that inherited repository write scope.

That combination allows compromise of repository integrity, including creating refs, pushing content, or otherwise abusing the write-scoped `GITHUB_TOKEN`/checkout credentials.

## Fix Requirement

External code builds must run without repository write permissions. PR creation and repository mutation must be isolated into a separate job that receives only the permissions it needs.

## Patch Rationale

The patch changes top-level workflow permissions from write access to read-only:

```yaml
permissions:
  contents: read
```

This causes `rebuild-libs` to run the external Cargo build without `contents: write` or `pull-requests: write`.

The patch then grants write permissions only to the `create-pr` job:

```yaml
permissions:
  contents: write
  pull-requests: write
```

That job consumes built artifacts and creates the bump PR, but it does not run `cargo build` inside the attacker-controlled external checkout.

## Residual Risk

None

## Patch

```diff
diff --git a/scripts/downstream-workflows/bump-nono-go.yml b/scripts/downstream-workflows/bump-nono-go.yml
index 9d9b9d6..b324120 100644
--- a/scripts/downstream-workflows/bump-nono-go.yml
+++ b/scripts/downstream-workflows/bump-nono-go.yml
@@ -11,8 +11,7 @@ on:
         type: string
 
 permissions:
-  contents: write
-  pull-requests: write
+  contents: read
 
 jobs:
   rebuild-libs:
@@ -78,6 +77,9 @@ jobs:
   create-pr:
     name: Create bump PR
     needs: rebuild-libs
+    permissions:
+      contents: write
+      pull-requests: write
     runs-on: ubuntu-latest
     env:
       NONO_VERSION: ${{ github.event.client_payload.nono_version || github.event.inputs.nono_version }}
```