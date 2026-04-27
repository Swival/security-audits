# Unpinned Network Installer Executes As Shell

## Classification

Trust-boundary violation, medium severity.

## Affected Locations

`library/portable-simd/.github/workflows/ci.yml:167`

## Summary

The `wasm-tests` GitHub Actions job installed `wasm-pack` by downloading `https://rustwasm.github.io/wasm-pack/installer/init.sh` at runtime and piping it directly to `sh`. Because the script was mutable network content and was not pinned, checksummed, signature-verified, or vendored, any change or compromise of that hosted installer would execute arbitrary shell commands in CI before the wasm tests ran.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

CI runs the `wasm-tests` job for a `pull_request` event.

## Proof

The workflow is triggered by `pull_request`. In the `wasm-tests` job, the `Install wasm-pack` step ran:

```yaml
run: curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```

This command downloaded installer content from a third-party URL at job runtime and executed it directly with `sh`. The command occurred immediately after `actions/checkout@v4` and before both wasm test steps, so modified or compromised installer content would execute in the CI runner before tests.

The original report referenced `library/portable-simd/.github/workflows/ci.yml:166`; reproduction confirmed the vulnerable `run:` command at `library/portable-simd/.github/workflows/ci.yml:167`, while line 166 was the step name.

## Why This Is A Real Bug

Executing mutable network content as shell code crosses a CI trust boundary. The workflow trusted external hosted installer content without pinning or integrity verification, allowing the installer host or any attacker able to alter the served script to run arbitrary commands in the GitHub Actions runner.

For pull request runs, forked PRs may have reduced token and secret access, but the runner still executes untrusted third-party code in the workflow context. That is sufficient practical impact for CI runner code execution before the intended test commands.

## Fix Requirement

Install `wasm-pack` from a pinned and reproducible source, such as a fixed Cargo crate version with lockfile enforcement, a pinned release artifact verified by checksum, or a committed/pinned action version. Do not pipe unverified network content directly to a shell.

## Patch Rationale

The patch replaces the network shell installer with:

```yaml
run: cargo install wasm-pack --version 0.12.1 --locked
```

This pins the installed `wasm-pack` version to `0.12.1` and uses Cargo’s `--locked` mode so dependency resolution follows the package lockfile rather than accepting arbitrary newer dependency versions. The CI job still installs `wasm-pack`, but no longer downloads a mutable installer script and executes it as shell code.

## Residual Risk

None

## Patch

```diff
diff --git a/library/portable-simd/.github/workflows/ci.yml b/library/portable-simd/.github/workflows/ci.yml
index de7efa35528..c154cc79cf5 100644
--- a/library/portable-simd/.github/workflows/ci.yml
+++ b/library/portable-simd/.github/workflows/ci.yml
@@ -164,7 +164,7 @@ jobs:
     steps:
       - uses: actions/checkout@v4
       - name: Install wasm-pack
-        run: curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
+        run: cargo install wasm-pack --version 0.12.1 --locked
       - name: Test (debug)
         run: wasm-pack test --firefox --headless crates/core_simd
         env:
```