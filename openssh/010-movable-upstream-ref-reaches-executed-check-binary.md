# movable upstream ref reaches executed check binary

## Classification

Command execution, high severity.

## Affected Locations

`mlkem768.sh:30`

## Summary

`mlkem768.sh` fetched and reset the `libcrux` checkout to the movable upstream ref `core-models-v0.0.4`, then copied generated headers from that checkout into `libcrux_mlkem768_sha3.h_new`, compiled a check program including that generated header, and executed the resulting binary. If the upstream ref was moved to attacker-controlled content, malicious C code in the generated headers could execute on the maintainer host during the extraction check.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A maintainer runs `mlkem768.sh`.
- The fetched `libcrux` ref resolves to attacker-controlled content.
- The attacker can influence the `libcrux` repository or the fetched ref target, such as by moving `core-models-v0.0.4`.

## Proof

The vulnerable script used a mutable revision selector:

```sh
WANT_LIBCRUX_REVISION="core-models-v0.0.4"
```

The script then fetched `libcrux`, reset the working tree to that name, and recorded the resulting commit:

```sh
git fetch
git checkout -B extract 1>&2
git reset --hard $WANT_LIBCRUX_REVISION 1>&2
LIBCRUX_REVISION=`git rev-parse HEAD`
```

Generated headers from the checked-out tree were copied into `libcrux_mlkem768_sha3.h_new` using `sed`. The filtering removed `#include` lines and trailing whitespace, but did not reject C declarations, definitions, constructors, or malicious function bodies.

The script then generated a check source file that includes the generated header:

```c
#include "libcrux_mlkem768_sha3.h_new"
```

It compiled and executed that check binary:

```sh
cc -Wall -Wextra -Wno-unused-parameter -I . -o libcrux_mlkem768_sha3_check \
	libcrux_mlkem768_sha3_check.c
./libcrux_mlkem768_sha3_check
```

An attacker-controlled generated header could therefore run code in the maintainer environment, for example via a GCC/Clang constructor using the already-included `<stdlib.h>` to call `system(...)`, or through malicious implementations of ML-KEM functions invoked by `main`.

## Why This Is A Real Bug

The script crosses a trust boundary by fetching upstream generated C content and immediately compiling and executing it. The selected upstream object was a movable ref name, not an immutable commit. If that name resolves to malicious content, the script does not verify the expected commit before the compile-and-run sink.

Modern Git behavior may avoid updating an already-existing local tag in some cases, but the path remains exploitable for a fresh clone or any local checkout that fetches or resolves the attacker-controlled ref.

## Fix Requirement

Pin the upstream dependency to an immutable commit hash and verify the resolved commit before compiling or executing any generated code.

## Patch Rationale

The patch replaces the movable ref with the immutable commit `026a87ab6d88ad3626b9fbbf3710d1e0483c1849`, quotes the revision argument passed to `git reset --hard`, and verifies that `git rev-parse HEAD` exactly matches the expected commit before continuing.

This ensures the script only compiles and executes generated code from the intended `libcrux` commit.

## Residual Risk

None

## Patch

```diff
diff --git a/mlkem768.sh b/mlkem768.sh
index bec372a..3093f75 100755
--- a/mlkem768.sh
+++ b/mlkem768.sh
@@ -4,7 +4,7 @@
 #
 
 #WANT_LIBCRUX_REVISION="origin/main"
-WANT_LIBCRUX_REVISION="core-models-v0.0.4"
+WANT_LIBCRUX_REVISION="026a87ab6d88ad3626b9fbbf3710d1e0483c1849"
 
 BASE="libcrux/libcrux-ml-kem/extracts/c_header_only/generated"
 FILES="
@@ -27,8 +27,9 @@ cd libcrux
 test `git diff | wc -l` -ne 0 && die "tree has unstaged changes"
 git fetch
 git checkout -B extract 1>&2
-git reset --hard $WANT_LIBCRUX_REVISION 1>&2
+git reset --hard "$WANT_LIBCRUX_REVISION" 1>&2
 LIBCRUX_REVISION=`git rev-parse HEAD`
+test "$LIBCRUX_REVISION" = "$WANT_LIBCRUX_REVISION" || die "libcrux revision mismatch"
 set +x
 
 cd $START
```