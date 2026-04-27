# cargo argument injection via environment

## Classification

Vulnerability, medium severity.

## Affected Locations

`library/stdarch/ci/run.sh:89`

## Summary

`ci/run.sh` accepted `TARGET` and `PROFILE` from the environment and interpolated them into a single shell command string used by `cargo_test`. The script then executed that string unquoted. If either environment variable contained spaces, shell word-splitting converted the embedded words into additional Cargo arguments.

This allowed an attacker who controls `TARGET` or `PROFILE` when invoking the script to inject Cargo flags such as `--config=build.rustc-wrapper=...`, altering build behavior.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

An attacker controls `TARGET` or `PROFILE` when invoking `library/stdarch/ci/run.sh`.

## Proof

`TARGET` is required from the environment and `PROFILE` is taken from the environment or defaulted to `release`. Neither value is validated before use.

Before the patch, `cargo_test` built a command string:

```sh
cmd="$cmd ${subcmd} --target=$TARGET --profile=$PROFILE $1"
cmd="$cmd -- $2"
```

It then executed the string unquoted:

```sh
$cmd
```

With a stub `cargo`, invoking the script with injected values produced separate arguments including:

```text
--target=x86_64-unknown-linux-gnu
--config=build.rustc-wrapper=/tmp/wrapper
--profile=release
--offline
```

This demonstrates that spaces inside `TARGET` or `PROFILE` become additional Cargo argv entries. The issue is reachable on each `cargo_test` call, including the `core_arch` and `examples` test paths.

## Why This Is A Real Bug

The intended invariant is that `TARGET` and `PROFILE` are single option values passed to Cargo as `--target=<value>` and `--profile=<value>`. The implementation violated that invariant by constructing a shell command string and executing it unquoted.

This is not direct shell metacharacter command execution, but it is argument injection into Cargo. Cargo accepts security-relevant flags such as `--config=build.rustc-wrapper=...`, which can cause an attacker-chosen wrapper executable to run during compilation if present.

## Fix Requirement

Do not construct a command as a shell string. Invoke Cargo using quoted argv elements so environment-derived values remain single arguments regardless of embedded spaces.

## Patch Rationale

The patch replaces string command construction with positional-parameter argv construction:

```sh
set -- cargo "${subcmd}" --target="${TARGET}" --profile="${PROFILE}"
```

Optional Cargo and test arguments are appended as quoted argv elements:

```sh
set -- "$@" "${cargo_arg}"
set -- "$@" --
set -- "$@" "${test_arg}"
```

The wasm `--nocapture` argument is also appended as a separate argv element. Cargo is then invoked with:

```sh
"$@"
```

This preserves the existing behavior while preventing shell word-splitting of `TARGET`, `PROFILE`, manifest-path arguments, and test arguments.

## Residual Risk

None

## Patch

```diff
diff --git a/library/stdarch/ci/run.sh b/library/stdarch/ci/run.sh
index ea012b42f98..a96b6819383 100755
--- a/library/stdarch/ci/run.sh
+++ b/library/stdarch/ci/run.sh
@@ -64,13 +64,20 @@ echo "STDARCH_TEST_SKIP_FUNCTION=${STDARCH_TEST_SKIP_FUNCTION}"
 echo "PROFILE=${PROFILE}"
 
 cargo_test() {
-    cmd="cargo"
+    cargo_arg=$1
+    test_arg=$2
     subcmd="test"
     if [ "$NORUN" = "1" ]; then
         export subcmd="build"
     fi
-    cmd="$cmd ${subcmd} --target=$TARGET --profile=$PROFILE $1"
-    cmd="$cmd -- $2"
+    set -- cargo "${subcmd}" --target="${TARGET}" --profile="${PROFILE}"
+    if [ -n "${cargo_arg}" ]; then
+        set -- "$@" "${cargo_arg}"
+    fi
+    set -- "$@" --
+    if [ -n "${test_arg}" ]; then
+        set -- "$@" "${test_arg}"
+    fi
 
     case ${TARGET} in
         # wasm targets can't catch panics so if a test failures make sure the test
@@ -83,10 +90,10 @@ cargo_test() {
               dir="debug"
             fi
             export CARGO_TARGET_WASM32_WASIP1_RUNNER="wasmtime -Wexceptions --dir /checkout/target/wasm32-wasip1/$dir/deps::."
-            cmd="$cmd --nocapture"
+            set -- "$@" --nocapture
             ;;
     esac
-    $cmd
+    "$@"
 }
 
 CORE_ARCH="--manifest-path=crates/core_arch/Cargo.toml"
```