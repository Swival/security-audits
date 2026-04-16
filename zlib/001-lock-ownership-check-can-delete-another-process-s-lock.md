# Lock ownership check can delete another process's lock

## Classification
- Type: race condition
- Severity: medium
- Confidence: certain

## Affected Locations
- `examples/gzlog.c:311`
- `examples/gzlog.c:396`
- `examples/gzlog.c:402`

## Summary
`log_lock()` records only the lock file `st_mtime` as ownership state. `log_unlock()` later relies on `log_check()` to compare the current file `st_mtime` against that saved value before unlinking the path. If the `.lock` file is deleted and recreated as a different inode within the same `time_t` second, the stale owner is misidentified as current owner and removes another process's lock.

## Provenance
- Verified by local reproduction against the committed code in `examples/gzlog.c`
- Patched in `001-lock-ownership-check-can-delete-another-process-s-lock.patch`
- Scanner provenance: https://swival.dev

## Preconditions
- Two processes contend for the same `.lock` path
- The original lock file is removed and recreated before the old owner calls `log_unlock()`
- The recreated file has the same second-level `st_mtime` value as the stale owner's recorded timestamp

## Proof
A local C harness included the committed `examples/gzlog.c`, created `foo.lock`, captured the saved ownership state, removed the file, recreated `foo.lock` as a new inode in the same second, and then invoked `log_unlock()`.

Observed output:
```text
saved mtime=1776358184 inode=85248701
new   mtime=1776358184 inode=85248702
exists after log_unlock=0
```

This demonstrates:
- the recreated lock was a different inode
- the saved and current `st_mtime` values matched
- `log_unlock()` deleted the recreated lock file anyway

## Why This Is A Real Bug
The lock is intended to provide mutual exclusion across processes. Using only second-granularity `st_mtime` as the ownership proof is insufficient because it does not bind ownership to a specific file instance. Once a stale owner can unlink a new owner's lock, exclusion is broken and concurrent writers can proceed under false assumptions. The reproduced behavior occurs through reachable normal unlock paths and is not merely theoretical.

## Fix Requirement
`log_unlock()` must verify ownership using a value that uniquely identifies the created lock instance before unlinking, such as inode/device metadata, an open file descriptor, or unique lock file contents, rather than `st_mtime` alone.

## Patch Rationale
The patch updates lock ownership tracking so unlock-time validation is tied to the actual created lock instance, not just its modification timestamp. This prevents a stale process from authenticating against a different lock file that happens to share the same second-level `mtime`, eliminating the reproduced false-positive ownership check before `unlink()`.

## Residual Risk
None

## Patch
The fix is contained in `001-lock-ownership-check-can-delete-another-process-s-lock.patch`.