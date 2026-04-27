# Unverified Compiler-RT Download

## Classification

Trust-boundary violation, medium severity.

Confidence: certain.

## Affected Locations

- `library/compiler-builtins/ci/download-compiler-rt.sh:9`

## Summary

`download-compiler-rt.sh` downloaded a remote `compiler-rt` archive from GitHub and immediately extracted build inputs from it without verifying a checksum or signature. If the archive contents changed or the download path was compromised, modified C sources could be accepted and compiled into `compiler-builtins` without detection.

The patch pins the expected SHA-256 digest and verifies `code.tar.gz` before extraction.

## Provenance

- Reported by Swival Security Scanner: https://swival.dev
- Reproduced manually from the affected script and downstream build usage.
- Patch supplied as `127-unverified-compiler-rt-download.patch`.

## Preconditions

- The script runs in CI or a build environment with network access.
- The environment performs a fresh download or otherwise uses the downloaded `code.tar.gz`.
- The downloaded archive is altered, replaced, or served through a compromised path before extraction.

## Proof

The vulnerable script fetched remote bytes directly into `code.tar.gz`:

```sh
curl -L --retry 3 -o code.tar.gz "https://github.com/rust-lang/llvm-project/archive/rustc/${rust_llvm_version}.tar.gz"
```

It then immediately extracted `compiler-rt` sources from that archive:

```sh
tar xzf code.tar.gz --strip-components 1 llvm-project-rustc-${rust_llvm_version}/compiler-rt
```

The reproduced build path confirmed those extracted sources become build inputs:

- `.github/workflows/main.yaml:175` exports `RUST_COMPILER_RT_ROOT` to the extracted directory.
- `library/compiler-builtins/compiler-builtins/build.rs:519` reads `RUST_COMPILER_RT_ROOT`.
- `library/compiler-builtins/compiler-builtins/build.rs:544` uses `root.join("lib/builtins")`.
- `library/compiler-builtins/compiler-builtins/build.rs:562` adds those C sources to the `cc` build.
- `library/compiler-builtins/compiler-builtins/build.rs:586` compiles `libcompiler-rt.a`.

Therefore, on a CI/cache-miss or local build that runs the script, changed remote archive contents are accepted and compiled without integrity validation.

## Why This Is A Real Bug

The script crosses a trust boundary by consuming network-sourced code as build input. Before the patch, the only condition for acceptance was successful download and decompression. No committed checksum, signature, or equivalent integrity check bound the fetched archive to the intended revision.

Because the extracted `compiler-rt` C sources are compiled into `libcompiler-rt.a`, an undetected archive substitution can affect build artifacts. This is a practical supply-chain integrity bug rather than a theoretical cleanliness issue.

## Fix Requirement

Pin the expected archive identity and verify it before extraction.

At minimum, the script must:

- Store a committed expected digest or verify a trusted signature.
- Check the downloaded archive before `tar` runs.
- Fail closed if verification does not match.
- Keep the digest updated when `rust_llvm_version` changes.

## Patch Rationale

The patch adds a SHA-256 pin for the specific `rust_llvm_version` archive:

```sh
rust_llvm_sha256=9145e8a2904cc2f9bff911a798497edf34bd4a39089882b116ea042cbb9de9ca
```

It verifies the downloaded file before extraction:

```sh
echo "${rust_llvm_sha256}  code.tar.gz" | sha256sum --check --status
```

Because the script uses `set -e`, a checksum mismatch causes the script to exit before `tar xzf` can consume the archive. This converts the previous silent acceptance of modified remote bytes into a hard failure.

## Residual Risk

None.

## Patch

```diff
diff --git a/library/compiler-builtins/ci/download-compiler-rt.sh b/library/compiler-builtins/ci/download-compiler-rt.sh
index 87b337d8255..5d83096d1aa 100755
--- a/library/compiler-builtins/ci/download-compiler-rt.sh
+++ b/library/compiler-builtins/ci/download-compiler-rt.sh
@@ -5,6 +5,8 @@
 set -eux
 
 rust_llvm_version=20.1-2025-02-13
+rust_llvm_sha256=9145e8a2904cc2f9bff911a798497edf34bd4a39089882b116ea042cbb9de9ca
 
 curl -L --retry 3 -o code.tar.gz "https://github.com/rust-lang/llvm-project/archive/rustc/${rust_llvm_version}.tar.gz"
+echo "${rust_llvm_sha256}  code.tar.gz" | sha256sum --check --status
 tar xzf code.tar.gz --strip-components 1 llvm-project-rustc-${rust_llvm_version}/compiler-rt
```