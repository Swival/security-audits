# Unpinned Remote Git Dependencies

## Classification

Trust-boundary violation, medium severity.

## Affected Locations

`library/compiler-builtins/builtins-test-intrinsics/Cargo.toml:14`

## Summary

The `builtins-test-intrinsics` manifest declared target-specific dev-dependencies from `https://github.com/japaric/utest` without an immutable `rev`. For matching ARM Linux non-GNU/non-musl test or dev dependency resolution, Cargo resolves the remote repository to the currently selected commit, allowing upstream changes to silently alter fetched test code during fresh lockfile generation or builds.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

ARM Linux non-GNU/non-musl dev-dependency resolution is performed for `library/compiler-builtins/builtins-test-intrinsics/Cargo.toml`.

## Proof

The affected manifest used three git dependencies with the same mutable remote URL and no `rev`, `tag`, or `branch` pin:

```toml
test = { git = "https://github.com/japaric/utest" }
utest-cortex-m-qemu = { default-features = false, git = "https://github.com/japaric/utest" }
utest-macros = { git = "https://github.com/japaric/utest" }
```

There is no committed `library/compiler-builtins/builtins-test-intrinsics/Cargo.lock`, and no existing committed lock entry for `git+https://github.com/japaric/utest`.

A practical resolution path exists at `library/compiler-builtins/ci/run-docker.sh:15`, which runs:

```sh
cargo generate-lockfile --manifest-path builtins-test-intrinsics/Cargo.toml
```

An equivalent Cargo manifest with the same target dev-dependencies fetched `https://github.com/japaric/utest` and generated lock entries such as:

```toml
source = "git+https://github.com/japaric/utest#e32073e2..."
```

This confirms Cargo resolves the manifest URL to the repository’s current selected commit at lock generation time.

## Why This Is A Real Bug

Without an immutable revision in the manifest or a committed lockfile, the dependency source crosses a trust boundary into mutable upstream state. Future fresh resolutions can select different code from the same repository URL without any local source change. The impact is constrained to test/dev builds or lockfile generation for the matching target, but the fetched dependency code can silently change.

## Fix Requirement

Pin each remote git dependency to an immutable commit hash using Cargo’s `rev` field.

## Patch Rationale

The patch adds the same immutable commit revision to all three dependencies sourced from `https://github.com/japaric/utest`:

```toml
rev = "e32073e2b078e3bee46001c13ae4c1acf368d762"
```

This preserves the existing dependency source and package selection while preventing Cargo from resolving the dependency to a different upstream commit during future fresh resolutions.

## Residual Risk

None

## Patch

```diff
diff --git a/library/compiler-builtins/builtins-test-intrinsics/Cargo.toml b/library/compiler-builtins/builtins-test-intrinsics/Cargo.toml
index fed2ac39fb3..633d2537c5f 100644
--- a/library/compiler-builtins/builtins-test-intrinsics/Cargo.toml
+++ b/library/compiler-builtins/builtins-test-intrinsics/Cargo.toml
@@ -11,9 +11,9 @@ compiler_builtins = { path = "../builtins-shim", features = ["compiler-builtins"
 panic-handler = { path = "../crates/panic-handler" }
 
 [target.'cfg(all(target_arch = "arm", not(any(target_env = "gnu", target_env = "musl")), target_os = "linux"))'.dev-dependencies]
-test = { git = "https://github.com/japaric/utest" }
-utest-cortex-m-qemu = { default-features = false, git = "https://github.com/japaric/utest" }
-utest-macros = { git = "https://github.com/japaric/utest" }
+test = { git = "https://github.com/japaric/utest", rev = "e32073e2b078e3bee46001c13ae4c1acf368d762" }
+utest-cortex-m-qemu = { default-features = false, git = "https://github.com/japaric/utest", rev = "e32073e2b078e3bee46001c13ae4c1acf368d762" }
+utest-macros = { git = "https://github.com/japaric/utest", rev = "e32073e2b078e3bee46001c13ae4c1acf368d762" }
 
 [features]
 c = ["compiler_builtins/c"]
```