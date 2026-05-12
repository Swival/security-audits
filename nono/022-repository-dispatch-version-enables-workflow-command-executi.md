# repository_dispatch Version Enables Workflow Command Execution

## Classification

Command execution, medium severity.

The `nono-release` dispatch is signed and triggered from the upstream `release.yml` via a write-scoped `DOWNSTREAM_PAT`. Reaching this bug requires either tampering with the upstream release pipeline or pushing a release tag whose name already contains shell metacharacters. The `workflow_dispatch` path requires write access to the downstream repository.

## Affected Locations

`scripts/downstream-workflows/bump-nono-py.yml:38`

## Summary

The `nono-release` `repository_dispatch` workflow accepted attacker-controlled `client_payload.nono_version`, stripped an optional `v` prefix, wrote the result to a step output, and later interpolated that output directly into a Bash command.

Because GitHub Actions expression interpolation occurs before Bash execution, a version containing shell command substitution such as `$(...)` was parsed and executed by the shell. The affected job ran with `contents: write` and `pull-requests: write` `GITHUB_TOKEN` permissions.

## Provenance

Found by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Attacker can send `nono-release` `repository_dispatch` events.
- Attacker controls `github.event.client_payload.nono_version`.

## Proof

Data flow:

- `scripts/downstream-workflows/bump-nono-py.yml:22` assigns `github.event.client_payload.nono_version` to `NONO_VERSION`.
- `scripts/downstream-workflows/bump-nono-py.yml:29` strips an optional `v` prefix.
- `scripts/downstream-workflows/bump-nono-py.yml:30` writes the attacker-derived value to `steps.version.outputs.version`.
- `scripts/downstream-workflows/bump-nono-py.yml:38` embeds `${{ steps.version.outputs.version }}` directly inside a double-quoted shell command:

```bash
EXISTING=$(gh pr list --search "bump nono to ${{ steps.version.outputs.version }}" --state open --json number --jq '.[0].number')
```

A payload such as:

```text
v1.2.3$(touch /tmp/pwned)
```

becomes shell syntax after GitHub expression interpolation. Bash then executes the `$(touch /tmp/pwned)` command substitution before invoking `gh pr list`.

The reproducer confirmed equivalent local shell behavior: `$(touch /tmp/pwned)` executed before `gh pr list` received its arguments.

## Why This Is A Real Bug

This is not only argument injection into `gh`; it is shell command execution caused by pre-shell GitHub expression interpolation.

The attacker-controlled value reaches a Bash script as source text rather than as safely quoted runtime data. Double quotes do not prevent command substitution in Bash, so `$(...)` remains executable.

The workflow grants:

```yaml
permissions:
  contents: write
  pull-requests: write
```

and the vulnerable step exposes:

```yaml
GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Therefore, arbitrary shell commands can execute in a privileged workflow context.

## Fix Requirement

The workflow must prevent untrusted version strings from being interpreted as shell syntax.

Acceptable fixes include:

- Validate `nono_version` against a strict allowed version format before writing it to outputs.
- Pass values through environment variables and quote shell variables at runtime.
- Avoid interpolating attacker-controlled GitHub expressions directly into `run` scripts.

## Patch Rationale

The patch adds strict SemVer-style validation immediately after stripping the optional `v` prefix:

```bash
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  echo "Invalid nono version: $NONO_VERSION" >&2
  exit 1
fi
```

This rejects shell metacharacters required for command substitution, including `$`, `(`, and `)`, before the value is written to `$GITHUB_OUTPUT`.

Only expected version strings such as `1.2.3`, `1.2.3-rc.1`, and `1.2.3+build.1` are allowed to proceed. Once the value is constrained to that grammar, the remaining `${{ steps.version.outputs.version }}` interpolations in later `run:` blocks can no longer expand into shell syntax, so the minimal patch is limited to the validation step. (Defense-in-depth — moving those later uses through `env:` like finding 019 and 023 — would still be welcome but is not required to close the command-execution hole.)

## Residual Risk

None

## Patch

```diff
diff --git a/scripts/downstream-workflows/bump-nono-py.yml b/scripts/downstream-workflows/bump-nono-py.yml
index 52e9cc7..9fa4cb6 100644
--- a/scripts/downstream-workflows/bump-nono-py.yml
+++ b/scripts/downstream-workflows/bump-nono-py.yml
@@ -27,6 +27,10 @@ jobs:
         id: version
         run: |
           VERSION="${NONO_VERSION#v}"
+          if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
+            echo "Invalid nono version: $NONO_VERSION" >&2
+            exit 1
+          fi
           echo "version=$VERSION" >> "$GITHUB_OUTPUT"
           echo "branch=bump-nono-${VERSION}" >> "$GITHUB_OUTPUT"
```