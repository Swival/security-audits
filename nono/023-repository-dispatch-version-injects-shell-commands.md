# repository_dispatch version injects shell commands

## Classification

Command execution, medium severity.

`nono-release` events are dispatched from the upstream `release.yml` via a write-scoped `DOWNSTREAM_PAT`, so reaching this bug requires either tampering with the upstream release pipeline or releasing a tag whose name already contains shell metacharacters. The `workflow_dispatch` entry point requires write access to the downstream repository.

## Affected Locations

`scripts/downstream-workflows/bump-nono-ts.yml:38`

## Summary

The `nono-release` `repository_dispatch` workflow accepted `github.event.client_payload.nono_version`, stripped only a leading `v`, wrote the result to `GITHUB_OUTPUT`, and later interpolated that value directly into `run:` shell scripts. Because GitHub expression interpolation occurs before shell execution, an attacker-controlled version string could break out of quoted shell context and execute arbitrary commands in a workflow with `contents: write` and `pull-requests: write`.

## Provenance

Found by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

An attacker can send `nono-release` `repository_dispatch` events and control `client_payload.nono_version`.

## Proof

The workflow sets:

```yaml
env:
  NONO_VERSION: ${{ github.event.client_payload.nono_version || github.event.inputs.nono_version }}
```

It then strips only a leading `v`:

```sh
VERSION="${NONO_VERSION#v}"
echo "version=$VERSION" >> "$GITHUB_OUTPUT"
```

The resulting output is interpolated into shell commands, including:

```yaml
VERSION="${{ steps.version.outputs.version }}"
```

A payload such as:

```text
v1.2.3"; touch /tmp/pwn; #
```

is transformed into:

```sh
VERSION="1.2.3"; touch /tmp/pwn; #"
```

Local simulation of Actions interpolation produced equivalent shell syntax and executed the injected command.

The same untrusted output was also interpolated into the `gh pr list --search` command.

## Why This Is A Real Bug

`github.event.client_payload.nono_version` is attacker-controlled under the stated precondition. Writing it to `GITHUB_OUTPUT` does not make it safe. Later use of `${{ steps.version.outputs.version }}` inside `run:` causes pre-shell interpolation, so shell metacharacters in the payload become executable syntax.

The workflow token is explicitly granted:

```yaml
permissions:
  contents: write
  pull-requests: write
```

Therefore successful exploitation provides arbitrary command execution in a privileged CI context.

## Fix Requirement

The workflow must reject non-version input before writing or using the value, and must avoid embedding untrusted GitHub expression output directly inside shell scripts. The version should be passed through `env` and consumed as a shell variable.

## Patch Rationale

The patch adds strict semantic-version validation before deriving outputs:

```sh
if ! [[ "$NONO_VERSION" =~ ^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]]; then
  echo "Invalid nono version: $NONO_VERSION" >&2
  exit 1
fi
```

This permits valid semver values with an optional leading `v`, while rejecting quotes, semicolons, command substitutions, whitespace, and other shell-control syntax.

The patch also changes shell steps to receive the validated version through `env`:

```yaml
env:
  VERSION: ${{ steps.version.outputs.version }}
```

and then use:

```sh
"$VERSION"
```

This removes direct `${{ ... }}` interpolation from the shell script body for the affected commands.

## Residual Risk

None

## Patch

```diff
diff --git a/scripts/downstream-workflows/bump-nono-ts.yml b/scripts/downstream-workflows/bump-nono-ts.yml
index e0c183f..976a403 100644
--- a/scripts/downstream-workflows/bump-nono-ts.yml
+++ b/scripts/downstream-workflows/bump-nono-ts.yml
@@ -26,6 +26,10 @@ jobs:
       - name: Strip v prefix
         id: version
         run: |
+          if ! [[ "$NONO_VERSION" =~ ^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]]; then
+            echo "Invalid nono version: $NONO_VERSION" >&2
+            exit 1
+          fi
           VERSION="${NONO_VERSION#v}"
           echo "version=$VERSION" >> "$GITHUB_OUTPUT"
           echo "branch=bump-nono-${VERSION}" >> "$GITHUB_OUTPUT"
@@ -34,8 +38,9 @@ jobs:
         id: check
         env:
           GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
+          VERSION: ${{ steps.version.outputs.version }}
         run: |
-          EXISTING=$(gh pr list --search "bump nono to ${{ steps.version.outputs.version }}" --state open --json number --jq '.[0].number')
+          EXISTING=$(gh pr list --search "bump nono to $VERSION" --state open --json number --jq '.[0].number')
           if [ -n "$EXISTING" ]; then
             echo "PR #$EXISTING already exists, skipping"
             echo "skip=true" >> "$GITHUB_OUTPUT"
@@ -45,8 +50,9 @@ jobs:
 
       - name: Update Cargo.toml
         if: steps.check.outputs.skip != 'true'
+        env:
+          VERSION: ${{ steps.version.outputs.version }}
         run: |
-          VERSION="${{ steps.version.outputs.version }}"
           # Update nono crate dependency
           sed -i "s/^nono[[:space:]]*=[[:space:]]*\"[^\"]*\"/nono = \"${VERSION}\"/" Cargo.toml
```