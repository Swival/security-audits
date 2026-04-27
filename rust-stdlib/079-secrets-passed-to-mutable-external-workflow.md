# Secrets Passed To Mutable External Workflow

## Classification

Trust-boundary violation, medium severity.

## Affected Locations

`library/stdarch/.github/workflows/rustc-pull.yml:13`

## Summary

The `rustc-pull` GitHub Actions workflow in `rust-lang/stdarch` invoked a reusable workflow from the external `rust-lang/josh-sync` repository using the mutable branch ref `@main`. The caller passed `ZULIP_API_TOKEN` and `APP_PRIVATE_KEY` secrets into that external workflow.

Any future change or compromise of `rust-lang/josh-sync` at `main` could cause attacker-controlled workflow code to run during scheduled or manually dispatched `stdarch` workflow executions with access to those secrets.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The workflow is executed by `workflow_dispatch` or the Monday/Thursday schedule.
- The job condition is satisfied: `github.repository == 'rust-lang/stdarch'`.
- `rust-lang/josh-sync` `main` changes maliciously or is compromised before a scheduled/manual run.

## Proof

The affected workflow defines scheduled and manual triggers:

```yaml
on:
  workflow_dispatch:
  schedule:
    - cron: '0 4 * * 1,4'
```

The reachable `pull` job invokes a reusable workflow from another repository using a mutable branch reference:

```yaml
uses: rust-lang/josh-sync/.github/workflows/rustc-pull.yml@main
```

The same job passes repository secrets into that reusable workflow:

```yaml
secrets:
  zulip-api-token: ${{ secrets.ZULIP_API_TOKEN }}
  github-app-secret: ${{ secrets.APP_PRIVATE_KEY }}
```

Because `@main` is mutable, later code committed to or injected into `rust-lang/josh-sync/.github/workflows/rustc-pull.yml` at `main` would execute under the caller workflow and receive those secrets.

## Why This Is A Real Bug

This crosses a trust boundary: a workflow in `rust-lang/stdarch` delegates execution to another repository while explicitly providing sensitive credentials. Branch references are not immutable, so the exact code that receives the secrets can change after review.

The exposed credentials are security-sensitive:

- `ZULIP_API_TOKEN` can be used to act as the configured Zulip bot.
- `APP_PRIVATE_KEY` can be used to authenticate as the configured GitHub App, subject to its installation permissions.

The attack path does not require modifying `stdarch`; changing or compromising the external workflow at `rust-lang/josh-sync@main` is sufficient before the next scheduled or manual run.

## Fix Requirement

Pin the reusable workflow reference to an immutable commit SHA, or to another ref with an equivalent immutability and trust guarantee.

## Patch Rationale

The patch replaces the mutable branch reference:

```yaml
uses: rust-lang/josh-sync/.github/workflows/rustc-pull.yml@main
```

with an immutable commit SHA:

```yaml
uses: rust-lang/josh-sync/.github/workflows/rustc-pull.yml@7e74618efc1838da65c111afd3053c0bead19744
```

This ensures the scheduled/manual workflow always executes the reviewed reusable workflow version, preventing later movement of `main` from changing the code that receives `ZULIP_API_TOKEN` and `APP_PRIVATE_KEY`.

## Residual Risk

None

## Patch

```diff
diff --git a/library/stdarch/.github/workflows/rustc-pull.yml b/library/stdarch/.github/workflows/rustc-pull.yml
index d2feb1add63..53d5b8030a0 100644
--- a/library/stdarch/.github/workflows/rustc-pull.yml
+++ b/library/stdarch/.github/workflows/rustc-pull.yml
@@ -10,7 +10,7 @@ on:
 jobs:
   pull:
     if: github.repository == 'rust-lang/stdarch'
-    uses: rust-lang/josh-sync/.github/workflows/rustc-pull.yml@main
+    uses: rust-lang/josh-sync/.github/workflows/rustc-pull.yml@7e74618efc1838da65c111afd3053c0bead19744
     with:
       github-app-id: ${{ vars.APP_CLIENT_ID }}
       pr-author: "workflows-stdarch[bot]"
```