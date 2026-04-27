# Unsafe Tar Extraction

## Classification

Medium severity vulnerability.

## Affected Locations

`library/compiler-builtins/ci/ci-util.py:464`

## Summary

`locate-baseline --download --extract` downloaded a benchmark baseline artifact, selected a matching `.tar.xz` archive via `glob(...)`, listed it with `tar tJf`, and extracted it with `tar xJf` without validating archive member paths.

A malicious or compromised artifact could include absolute paths, `..` traversal components, or unsafe link targets and write files outside the intended `gungraun-home` area during extraction.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `locate-baseline` is run with `--download --extract`.
- The downloaded artifact contents are untrusted or attacker-influenced.
- The artifact name matches the expected baseline glob.

## Proof

The vulnerable flow is reachable through the documented CI utility command:

```sh
python3 library/compiler-builtins/ci/ci-util.py locate-baseline --download --extract --tag x86_64
```

The reproduced trigger used a fake `gh` command that returned a successful CI run and downloaded a matching artifact containing:

```text
gungraun-home/expected-baseline
OUTSIDE_GUNGRAUN_PROOF
```

Running the command created:

```text
./OUTSIDE_GUNGRAUN_PROOF
```

outside `gungraun-home` and printed:

```text
baseline extracted successfully
```

The affected code listed the archive:

```python
all_paths = sp.check_output(["tar", "tJf", baseline_archive], encoding="utf8")
```

then extracted it directly:

```python
sp.run(["tar", "xJf", baseline_archive], check=True)
```

with no path or link-target validation between those operations.

## Why This Is A Real Bug

The utility explicitly supports downloading and extracting CI artifacts. Artifact contents are not inherently trustworthy, especially if a workflow artifact can be malicious, compromised, replaced, or otherwise attacker-influenced.

Tar extraction preserves archive member paths. Without validation, members such as:

```text
../some-file
/path/outside/workspace
```

or links targeting paths outside the intended directory can cause writes outside `gungraun-home`.

Impact is limited to the permissions of the CI user or local user running the command, but that still permits overwriting source, configuration, benchmark inputs, or build files in the checkout before later steps run.

## Fix Requirement

Before extraction, inspect every tar member and reject:

- Absolute member paths.
- Member paths containing parent traversal components.
- Symlink or hardlink targets that are absolute.
- Symlink or hardlink targets containing parent traversal components.

Extraction must not proceed if any unsafe member or link target is present.

## Patch Rationale

The patch opens the selected archive with Python’s `tarfile` module before invoking `tar xJf`.

For each member, it parses the archive path as a POSIX path:

```python
path = PurePosixPath(member.name)
```

and rejects absolute paths or paths containing `..`.

For symlinks and hardlinks, it also parses and validates `member.linkname`, rejecting absolute or parent-traversing targets.

Only after all members pass validation does the existing extraction command run. This preserves the current extraction behavior for valid artifacts while blocking archive traversal payloads.

## Residual Risk

None

## Patch

```diff
diff --git a/library/compiler-builtins/ci/ci-util.py b/library/compiler-builtins/ci/ci-util.py
index f359c597974..86bc9027beb 100755
--- a/library/compiler-builtins/ci/ci-util.py
+++ b/library/compiler-builtins/ci/ci-util.py
@@ -11,12 +11,13 @@ import pprint
 import re
 import subprocess as sp
 import sys
+import tarfile
 from dataclasses import dataclass, field
 from functools import cache
 from glob import glob
 from inspect import cleandoc
 from os import getenv
-from pathlib import Path
+from pathlib import Path, PurePosixPath
 from typing import TypedDict, Self
 
 USAGE = cleandoc("""
@@ -464,6 +465,17 @@ def locate_baseline(flags: list[str]) -> None:
     eprint(f"extracting {baseline_archive}")
 
     all_paths = sp.check_output(["tar", "tJf", baseline_archive], encoding="utf8")
+    with tarfile.open(baseline_archive, "r:xz") as archive:
+        for member in archive:
+            path = PurePosixPath(member.name)
+            if path.is_absolute() or ".." in path.parts:
+                raise ValueError(f"refusing to extract unsafe path: {member.name}")
+            if member.islnk() or member.issym():
+                link = PurePosixPath(member.linkname)
+                if link.is_absolute() or ".." in link.parts:
+                    raise ValueError(
+                        f"refusing to extract unsafe link target: {member.linkname}"
+                    )
     sp.run(["tar", "xJf", baseline_archive], check=True)
 
     # Print a short summary of paths, we don't use `tar v` since the list is huge
```