# Access log write failures are silently ignored

## Classification
- Type: error-handling bug
- Severity: low
- Confidence: certain

## Affected Locations
- `lib/handler/access_log.c:40`

## Summary
`log_access` formats each request log entry and emits it with a single `write(2)` call whose return value is ignored. If the sink returns `-1` or a short count, the entry is silently dropped or truncated. This affects file, pipe, and UNIX-domain socket outputs when access logging is enabled.

## Provenance
- Verified finding reproduced from the provided report and reproducer notes
- Scanner provenance: https://swival.dev

## Preconditions
- Access logging is enabled
- The configured log sink returns an error or a short write

## Proof
At `lib/handler/access_log.c:40`, `log_access` passes the formatted buffer from `h2o_log_request` directly to `write(fh->fd, logline, len)` and does not inspect the result.
The reproducer establishes:
- The server ignores `SIGPIPE` in `src/main.c:3966`, so broken pipe or socket peers cause `write` to return `-1` with `EPIPE` instead of terminating the process
- Access log lines can exceed the stack buffer because `h2o_log_request` reallocates as needed in `lib/core/logconf.c:548`
- Request inputs can be large by default via `include/h2o.h:67`

Therefore, both complete failures and partial writes are reachable, and the current implementation silently loses log data.

## Why This Is A Real Bug
Ignoring `write(2)` results violates the contract of the API for non-regular-file sinks and for error conditions on any sink. A short write does not mean the full record was persisted, and `-1` means nothing was written. Because access logs are operational evidence, silent loss or truncation is a correctness defect even at low severity.

## Fix Requirement
Handle `write(2)` correctly by:
- Checking the return value
- Retrying until all `len` bytes are written or an unrecoverable error occurs
- Preserving interruption semantics by retrying on transient interruption
- Reporting or surfacing unrecoverable failures instead of silently ignoring them

## Patch Rationale
The patch wraps access-log emission in a bounded write loop in `lib/handler/access_log.c`, advances the buffer on successful partial writes, retries on interrupt, and stops on unrecoverable failure. This guarantees that complete records are attempted and prevents silent truncation from a single short write.

## Residual Risk
None

## Patch
- Patch file: `013-access-log-writes-ignore-i-o-failures.patch`
- Patched location: `lib/handler/access_log.c`
- Implemented behavior:
  - loops until the full log line is written
  - retries on `EINTR`
  - stops on hard write failure instead of pretending success