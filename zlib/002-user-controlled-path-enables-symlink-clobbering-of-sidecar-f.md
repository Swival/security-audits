# User-controlled sidecar path allows symlink clobbering

## Classification
- Type: vulnerability
- Severity: medium
- Confidence: certain

## Affected Locations
- `examples/gzlog.c:682`
- `examples/gzlog.c:720`

## Summary
`gzlog` derives sidecar paths from a caller-controlled base path and opens `<path>.add` and `<path>.temp` with truncating create flags. Those `open()` calls follow pre-existing symlinks, so an attacker who can plant directory entries under the chosen path can cause writes to truncate or overwrite an external file reachable by the symlink target.

## Provenance
- Verified reproduced finding based on local harness results and source review
- Scanner origin: [Swival Security Scanner](https://swival.dev)

## Preconditions
- The attacker controls directory entries for the user-supplied `path` before `gzlog` performs write or compression operations.
- The process using `gzlog` has write permission to the symlink target file.

## Proof
- `gzlog_open()` retains the caller-supplied base path and later code appends sidecar suffixes in-place.
- `gzlog_write()` opens `<path>.add` with `open(..., O_WRONLY | O_CREAT | O_TRUNC, 0644)` at `examples/gzlog.c:682`.
- `gzlog_compress()` opens `<path>.temp` with `open(..., O_WRONLY | O_CREAT | O_TRUNC, 0644)` at `examples/gzlog.c:720`.
- Reproduction created `/tmp/gzlogtest/log.add -> /tmp/gzlogtest/victim`, then invoked `gzlog_open("/tmp/gzlogtest/log")` and `gzlog_write(..., "HELLO", 5)`.
- The target `/tmp/gzlogtest/victim` changed from `SECRET-DATA\n` to exactly 5 bytes `HELLO`, demonstrating that `open(... | O_TRUNC)` followed the symlink and clobbered the external file.

## Why This Is A Real Bug
The vulnerable behavior is directly observable: a planted symlink causes `gzlog` to truncate and rewrite a different file than the intended sidecar. The `.lock` file only serializes access to `<path>.lock`; it does not authenticate or safely create `<path>.add` or `<path>.temp`. Because the process performs the destructive open itself, this is a concrete arbitrary file overwrite primitive within the process's write permissions.

## Fix Requirement
Open derived sidecar files without following symlinks and avoid truncating attacker-controlled existing paths. The fix must reject symlinked sidecars and ensure the opened object is the expected regular file before use.

## Patch Rationale
The patch updates sidecar creation to use `O_NOFOLLOW | O_EXCL` and validates the resulting file as a regular file before writing. This prevents pre-planted symlinks from being followed and removes the truncation-on-open behavior that enabled external file clobbering.

## Residual Risk
None

## Patch
- `002-user-controlled-path-enables-symlink-clobbering-of-sidecar-f.patch` hardens sidecar opens in `examples/gzlog.c` by rejecting symlinks and requiring safe file creation semantics for `.add` and `.temp`.
- The change aligns with the verified exploit path and blocks the reproduced overwrite primitive without altering the caller-facing path API.