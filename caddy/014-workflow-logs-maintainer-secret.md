# workflow logs maintainer secret

## Classification

Information disclosure, medium severity. Confidence: certain.

## Affected Locations

`.github/workflows/auto-release-pr.yml:58`

## Summary

The release proposal approval workflow exposed the secret-derived maintainer allowlist in GitHub Actions logs. The workflow passed `secrets.MAINTAINER_LOGINS` into `MAINTAINER_LOGINS`, parsed it into `maintainerLogins`, then logged the normalized list with:

```js
console.log(`Maintainer logins: ${maintainerLogins.join(', ')}`);
```

Any repository actor with access to the relevant Actions run logs could read the maintainer list, even if they could not read repository Actions secrets directly.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `MAINTAINER_LOGINS` secret is configured.
- Workflow logs are accessible to the attacker.
- A `release-proposal` pull request event triggers the `check-approvals` job.

## Proof

The workflow is reachable for open pull requests labeled `release-proposal` via `pull_request_review` and `pull_request` events.

The affected job passes the secret into the script environment:

```yaml
env:
  MAINTAINER_LOGINS: ${{ secrets.MAINTAINER_LOGINS }}
```

The script then reads, splits, trims, and filters that value:

```js
const maintainerLoginsRaw = process.env.MAINTAINER_LOGINS || '';
const maintainerLogins = maintainerLoginsRaw
  .split(/[,;]/)
  .map(login => login.trim())
  .filter(login => login.length > 0);
```

Before the patch, it printed the resulting list:

```js
console.log(`Maintainer logins: ${maintainerLogins.join(', ')}`);
```

For a supported secret value such as:

```text
alice,bob; carol
```

the workflow log would contain:

```text
Maintainer logins: alice, bob, carol
```

This discloses a delimiter-normalized secret-derived maintainer ACL.

## Why This Is A Real Bug

GitHub Actions secrets are intended to be unavailable to lower-privileged repository actors. This workflow transformed a secret value and explicitly wrote the transformed contents to logs. GitHub secret masking is not a reliable mitigation here because the emitted value can differ from the raw secret literal due to splitting, trimming, delimiter normalization, and rejoining.

The exposed data is security-relevant because it identifies the maintainer identities used to determine release approval quorum.

## Fix Requirement

Do not log `MAINTAINER_LOGINS` or values derived from it. If operational visibility is needed, log only non-sensitive aggregate information, such as the count of configured maintainers.

## Patch Rationale

The patch removes the sensitive log statement:

```diff
-            console.log(`Maintainer logins: ${maintainerLogins.join(', ')}`);
```

The parsed maintainer list remains available for approval checks, so workflow behavior is preserved while preventing disclosure of the secret-derived allowlist.

## Residual Risk

None

## Patch

```diff
diff --git a/.github/workflows/auto-release-pr.yml b/.github/workflows/auto-release-pr.yml
index c8440d32..3b637117 100644
--- a/.github/workflows/auto-release-pr.yml
+++ b/.github/workflows/auto-release-pr.yml
@@ -55,8 +55,6 @@ jobs:
               .map(login => login.trim())
               .filter(login => login.length > 0);
             
-            console.log(`Maintainer logins: ${maintainerLogins.join(', ')}`);
-            
             // Get the latest review from each user
             const latestReviewsByUser = {};
             reviews.data.forEach(review => {
```