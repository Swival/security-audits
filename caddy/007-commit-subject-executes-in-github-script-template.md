# Commit Subject Executes In GitHub-Script Template

## Classification

High severity code execution.

## Affected Locations

`.github/workflows/release-proposal.yml:183`

## Summary

The release proposal workflow embedded changelog text derived from commit subjects directly inside a JavaScript template literal in `actions/github-script`.

A malicious commit subject containing JavaScript template interpolation, such as `${console.log("PWNED")}`, survived changelog generation and executed when the workflow evaluated:

```js
const changelog = `${{ steps.setup.outputs.changelog }}`;
```

The job grants `contents: write`, `pull-requests: write`, and `issues: write`, so this enabled attacker-controlled JavaScript execution in a privileged workflow context.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A maintainer runs the release proposal workflow against release history that includes an attacker-controlled commit subject.

## Proof

The changelog is generated from commit subjects using:

```sh
git log --pretty=format:"- %s (%h)"
```

The workflow only escaped backticks before writing the changelog to `steps.setup.outputs.changelog`:

```sh
CLEANSED_COMMITS=$(echo "$COMMITS" | sed 's/`/\\`/g')
```

This does not escape JavaScript template interpolation syntax.

A commit subject of:

```text
${console.log("PWNED")}
```

produced changelog text equivalent to:

```text
- ${console.log("PWNED")} (...)
```

That value was then embedded into:

```js
const changelog = `${{ steps.setup.outputs.changelog }}`;
```

At runtime, JavaScript interpreted `${console.log("PWNED")}` as template literal interpolation and executed it inside `actions/github-script`.

## Why This Is A Real Bug

The attacker-controlled commit subject crosses from Git history into executable JavaScript syntax without safe encoding.

Escaping backticks is insufficient because JavaScript template literals also evaluate `${...}` expressions. GitHub Actions expression substitution occurs before the `actions/github-script` JavaScript is evaluated, so the resulting script contains attacker-controlled executable interpolation.

The impact is privileged workflow code execution because the affected job has write permissions for repository contents, pull requests, and issues.

## Fix Requirement

Do not inline untrusted changelog text into JavaScript source code.

Pass the changelog as data through an environment variable or JSON-encode it before JavaScript use.

## Patch Rationale

The patch moves the changelog into the step environment:

```yaml
env:
  CHANGELOG: ${{ steps.setup.outputs.changelog }}
```

The script then reads it as data:

```js
const changelog = process.env.CHANGELOG;
```

This prevents commit subjects from becoming part of the JavaScript program text. `${...}` remains literal changelog content instead of executable template interpolation.

## Residual Risk

None

## Patch

```diff
diff --git a/.github/workflows/release-proposal.yml b/.github/workflows/release-proposal.yml
index 0b9a0913..58f1522b 100644
--- a/.github/workflows/release-proposal.yml
+++ b/.github/workflows/release-proposal.yml
@@ -178,9 +178,11 @@ jobs:
       - name: Create release proposal PR
         id: create_pr
         uses: actions/github-script@ed597411d8f924073f98dfc5c65a23a2325f34cd # v8.0.0
+        env:
+          CHANGELOG: ${{ steps.setup.outputs.changelog }}
         with:
           script: |
-            const changelog = `${{ steps.setup.outputs.changelog }}`;
+            const changelog = process.env.CHANGELOG;
             
             const pr = await github.rest.pulls.create({
               owner: context.repo.owner,
```