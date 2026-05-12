# dispatch version executes shell commands in privileged workflow

## Classification

Command execution, medium severity.

The workflow is one of the downstream-bump templates shipped from this repository. In production, `repository_dispatch` events arrive from the upstream `release.yml` (`scripts/.github/workflows/release.yml:244`) via a write-scoped `DOWNSTREAM_PAT`, so triggering the bug requires either tampering with the release pipeline or releasing a tag whose name contains shell metacharacters. The `workflow_dispatch` path likewise requires write access to the downstream repo. The blast radius is real (privileged `GITHUB_TOKEN` writes to a downstream repo), but the precondition is not a remote unauthenticated attacker.

## Affected Locations

- `scripts/downstream-workflows/bump-nono-registry.yml:13`
- `scripts/downstream-workflows/bump-nono-registry.yml:22`
- `scripts/downstream-workflows/bump-nono-registry.yml:30`
- `scripts/downstream-workflows/bump-nono-registry.yml:38`
- `scripts/downstream-workflows/bump-nono-registry.yml:49`
- `scripts/downstream-workflows/bump-nono-registry.yml:58`

## Summary

The privileged `repository_dispatch` workflow accepted `client_payload.nono_version`, propagated it into a step output, and interpolated that output directly into shell script source. A malicious version containing shell command substitution, such as `v0.33.0$(id >&2)`, was rendered into bash and executed with `contents: write` and `pull-requests: write` permissions.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

The finding was reproduced and patched.

## Preconditions

- An attacker can send or influence `repository_dispatch` events for type `nono-release`.
- The attacker controls `github.event.client_payload.nono_version`.
- The workflow runs with the declared privileged `GITHUB_TOKEN` permissions.

## Proof

The workflow sets:

```yaml
env:
  NONO_VERSION: ${{ github.event.client_payload.nono_version || github.event.inputs.nono_version }}
```

The `Strip v prefix` step derives output directly from this value:

```bash
VERSION="${NONO_VERSION#v}"
echo "version=$VERSION" >> "$GITHUB_OUTPUT"
```

That output is later embedded into shell source:

```bash
EXISTING=$(gh pr list --search "bump nono to ${{ steps.version.outputs.version }}" --state open --json number --jq '.[0].number')
```

and:

```bash
VERSION="${{ steps.version.outputs.version }}"
```

For payload:

```text
v0.33.0$(id >&2)
```

the generated shell contains:

```bash
VERSION="0.33.0$(id >&2)"
```

Bash evaluates `$(id >&2)` during execution. The same attacker-controlled output is also interpolated into the `gh pr list` command and `cargo update` command paths.

## Why This Is A Real Bug

GitHub Actions expression interpolation happens before the shell script is executed. Values inserted with `${{ ... }}` are not shell-escaped. Therefore, attacker-controlled content containing command substitution becomes executable shell syntax when rendered into a `run:` block.

The job has:

```yaml
permissions:
  contents: write
  pull-requests: write
```

so injected commands run in a workflow context capable of writing repository contents and pull requests. The reproduced payload demonstrates command execution before the intended dependency update logic.

## Fix Requirement

- Reject unsafe `nono_version` values before writing outputs or using them in shell commands.
- Enforce a strict release tag format, such as `^v[0-9]+\.[0-9]+\.[0-9]+$`.
- Avoid directly interpolating step outputs into shell script source when the value is used as shell data.
- Pass trusted values through `env:` where shell expansion treats them as variable contents rather than source code.

## Patch Rationale

The patch adds validation in the first shell step before deriving `VERSION`:

```bash
if [[ ! "$NONO_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Invalid nono_version: $NONO_VERSION" >&2
  exit 1
fi
```

This blocks command substitutions, metacharacters, whitespace, prerelease suffixes, and arbitrary shell syntax before the value is written to `$GITHUB_OUTPUT`.

The patch also changes the `Update Cargo.toml` step to pass the validated version via `env:`:

```yaml
env:
  VERSION: ${{ steps.version.outputs.version }}
```

and removes the vulnerable shell assignment:

```bash
VERSION="${{ steps.version.outputs.version }}"
```

This prevents that step from rendering attacker-controlled text directly into shell source.

## Residual Risk

None

## Patch

```diff
diff --git a/scripts/downstream-workflows/bump-nono-registry.yml b/scripts/downstream-workflows/bump-nono-registry.yml
index 30e965f..212b58c 100644
--- a/scripts/downstream-workflows/bump-nono-registry.yml
+++ b/scripts/downstream-workflows/bump-nono-registry.yml
@@ -26,6 +26,10 @@ jobs:
       - name: Strip v prefix
         id: version
         run: |
+          if [[ ! "$NONO_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
+            echo "Invalid nono_version: $NONO_VERSION" >&2
+            exit 1
+          fi
           VERSION="${NONO_VERSION#v}"
           echo "version=$VERSION" >> "$GITHUB_OUTPUT"
           echo "branch=bump-nono-${VERSION}" >> "$GITHUB_OUTPUT"
@@ -45,8 +49,9 @@ jobs:
 
       - name: Update Cargo.toml
         if: steps.check.outputs.skip != 'true'
+        env:
+          VERSION: ${{ steps.version.outputs.version }}
         run: |
-          VERSION="${{ steps.version.outputs.version }}"
           # Update nono workspace dependency
           sed -i "s/^nono[[:space:]]*=[[:space:]]*\"[^\"]*\"/nono = \"${VERSION}\"/" Cargo.toml
```