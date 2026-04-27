#!/usr/bin/env bash
# bug: library/compiler-builtins/ci/download-compiler-rt.sh fetches a remote tarball
#      and immediately extracts it as build inputs without verifying a checksum.
# expected: archive must be checksummed against a pinned digest before extraction.
# observed: any modified or substituted archive is silently accepted and extracted.
# target: any. This is a minimal mock of the curl|tar pattern, no real download.
# build/run: bash 127-unverified-compiler-rt-download.sh

set -eu

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR"

mkdir -p upstream/llvm-project-rustc-fake/compiler-rt/lib/builtins
echo "// legitimate compiler-rt source" > upstream/llvm-project-rustc-fake/compiler-rt/lib/builtins/legit.c
( cd upstream && tar czf legit.tar.gz llvm-project-rustc-fake )
LEGIT_SHA=$(shasum -a 256 upstream/legit.tar.gz | awk '{print $1}')

mkdir -p tampered/llvm-project-rustc-fake/compiler-rt/lib/builtins
echo "// MALICIOUS substituted source" > tampered/llvm-project-rustc-fake/compiler-rt/lib/builtins/legit.c
( cd tampered && tar czf tampered.tar.gz llvm-project-rustc-fake )
TAMPERED_SHA=$(shasum -a 256 tampered/tampered.tar.gz | awk '{print $1}')

vulnerable_download() {
    cp tampered/tampered.tar.gz code.tar.gz
    tar xzf code.tar.gz --strip-components 1 llvm-project-rustc-fake/compiler-rt
    cat compiler-rt/lib/builtins/legit.c
}

fixed_download() {
    cp tampered/tampered.tar.gz code.tar.gz
    echo "${LEGIT_SHA}  code.tar.gz" | shasum -a 256 -c -s
    tar xzf code.tar.gz --strip-components 1 llvm-project-rustc-fake/compiler-rt
}

mkdir vuln_run && cd vuln_run
output=$(vulnerable_download 2>&1)
cd ..
if echo "$output" | grep -q MALICIOUS; then
    echo "BUG TRIGGERED: vulnerable script accepted tampered tarball:"
    echo "$output"
else
    echo "FAIL: tampered content not extracted"
    exit 1
fi

mkdir fix_run && cd fix_run
if fixed_download 2>/dev/null; then
    echo "FAIL: fixed script accepted tampered tarball"
    exit 1
else
    echo "FIX OK: pinned-checksum variant rejected the tampered tarball"
fi
