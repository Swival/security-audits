# POSIX file growth ignores syscall failures

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/mmfile.d:300`

## Summary
- The POSIX writable mapping constructors grow the backing file with `lseek(fd, size - 1, SEEK_SET)` and `write(fd, &c, 1)` but do not check either return value.
- If either syscall fails, constructor state still records the requested larger mapping size and proceeds to `mmap`, violating the invariant that the file is at least `this.size` bytes long.
- This can produce a successfully constructed mapping whose later accesses fault with `SIGBUS` or whose writes do not persist as expected.

## Provenance
- Verified by local reproduction on this worktree host.
- Source review and patch prepared from `std/mmfile.d`.
- Reference: Swival Security Scanner, https://swival.dev

## Preconditions
- POSIX writable mapping extends a file.
- `lseek` or the final extending `write` fails, such as under `RLIMIT_FSIZE`, `ENOSPC`, or `EDQUOT`.

## Proof
- The affected constructor path receives user-controlled `size` and, when growth is needed, executes `lseek(fd, size - 1, SEEK_SET)` followed by a one-byte `write`.
- In the vulnerable code, both return values are ignored and execution continues to set `this.size` and invoke `mmap(..., initial_map, ..., fd, 0)`.
- Reproduction on the host used `RLIMIT_FSIZE=1` with a new file and requested length `10`:
  - `lseek(fd, 9, SEEK_SET)` succeeded.
  - `write(fd, &c, 1)` failed with `errno=27` (`EFBIG`).
  - `fstat` still reported file size `0`.
  - `mmap(..., 10, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)` succeeded.
  - First access into the mapping raised `SIGBUS`.
- This demonstrates constructor success despite failed file growth and a faulting mapping beyond EOF.

## Why This Is A Real Bug
- The constructor reports success for an invalid object state: `this.size` exceeds the real file length.
- POSIX permits mapping a length larger than the current file size; failure is deferred until access, making ignored syscall failures directly exploitable into runtime faults.
- The bug is practical, not theoretical: the reproduced `EFBIG` case shows a common failure mode where `mmap` succeeds and later access crashes.

## Fix Requirement
- Check the return value of both `lseek` and the extending `write`.
- On either failure, abort construction before setting the final size or calling `mmap`.
- If the constructor owns the descriptor in that path, close it before throwing.

## Patch Rationale
- The patch in `025-posix-file-growth-ignores-syscall-failures.patch` adds explicit error handling for both growth syscalls in the POSIX path.
- It throws immediately on failure, preventing `this.size` from diverging from the actual file length and preventing creation of a mapping beyond EOF.
- This restores the constructor invariant that a successful writable mapping only exists when the backing file has been successfully extended.

## Residual Risk
- None

## Patch
- `025-posix-file-growth-ignores-syscall-failures.patch` validates `lseek` and `write` during POSIX file growth and fails the constructor before mapping when either syscall does not succeed.