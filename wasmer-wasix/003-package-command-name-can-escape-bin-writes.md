# Package command names can escape intended `/bin` write targets

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/wasix/src/state/env.rs:755`

## Summary
Package command names and mapped command aliases were interpolated directly into `/bin/{name}` and `/usr/bin/{name}` paths during package loading. Because the code did not enforce basename-only semantics, slash-containing names could redirect writes to unintended locations within the mounted WASI root, and host-backed roots could also honor `..` traversal components.

## Provenance
- Reported from verified reproduction and patching workflow
- Scanner: https://swival.dev

## Preconditions
- A package command name or `map_commands` key contains path separators or `..`
- Package loading or command mapping reaches the filesystem write path

## Proof
`use_package_async()` and `map_commands()` constructed command destinations with `format!("/bin/{}", ...)` and `/usr/bin/...`, then passed those paths to `write_readonly_buffer_to_fs()`.

That helper creates parent directories and opens the supplied path as-is. It did not re-check that the final target remained a single command slot under `/bin` or `/usr/bin`.

Reproduction confirmed that a slash-containing command name writes outside the intended command path inside the mounted WASI root. The verified reproduction also established an important bound: on the default tmpfs-backed `mem_fs` path, `..` commonly fails rather than escaping because that backend does not canonicalize `..` in this write flow. On host-backed roots, however, traversal semantics remain dangerous if unchecked.

## Why This Is A Real Bug
This is a real arbitrary-write-within-root condition during package installation and command mapping, not a cosmetic path issue.

- The vulnerable input is used in filesystem path construction, not just logging or lookup
- The sink performs real writes and parent directory creation
- Slash-containing names reliably create unintended nested targets under the mounted root
- The impact is security-relevant even without host escape because package metadata can overwrite arbitrary files within the WASI root and bypass the intended `/bin` command-slot boundary

The reproduction narrows one part of the original claim: `..` does not reliably escape on the default `mem_fs` fast path. That does not negate the bug, because path-separator injection is still reachable and exploitable, and host-backed filesystems may interpret traversal components.

## Fix Requirement
Reject command names unless they are normalized single path components before any filesystem write or alias mapping occurs.

## Patch Rationale
The patch adds basename validation for package command names and mapped command aliases in `lib/wasix/src/state/env.rs`, ensuring only a single non-traversing path component is accepted before constructing `/bin/...` or `/usr/bin/...` destinations.

This is the narrowest correct fix because it enforces the actual invariant the code relies on: command names are filenames, not paths. Blocking invalid names at the source prevents both nested-path writes and traversal-sensitive backend behavior.

## Residual Risk
None

## Patch
Patched in `003-package-command-name-can-escape-bin-writes.patch`.