# Output write failures return success

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `examples/gzjoin.c:229`
- `examples/gzjoin.c`

## Summary
`examples/gzjoin.c` writes gzip output to `stdout` via `fwrite()` and `putc()` but does not check for short writes or `EOF`. When `stdout` is closed, full, or otherwise failing, output generation truncates or produces nothing, yet processing continues and `main()` still exits `0`.

## Provenance
- Verified finding reproduced from the provided report
- Scanner source: https://swival.dev
- Reproducer built and exercised the failing path with `stdout` closed

## Preconditions
- `stdout` write fails during output generation

## Proof
The reproduced case compiles `examples/gzjoin.c`, then runs it with file descriptor `1` closed:

```sh
printf 'sample data for gzjoin reproduction\n' > /tmp/gzjoin_input.txt
gzip -c /tmp/gzjoin_input.txt > /tmp/gzjoin_input.txt.gz
cc -I. examples/gzjoin.c adler32.c crc32.c inflate.c inftrees.c inffast.c zutil.c -o /tmp/gzjoin_test
sh -c 'exec 1>&-; /tmp/gzjoin_test /tmp/gzjoin_input.txt.gz; rc=$?; echo EXIT:$rc >&2'
```

Observed result:

```text
EXIT:0
```

This demonstrates that all output writes can fail while the program still reports success. The root cause is unchecked `fwrite()`/`putc()` calls in the output path and the absence of any final `fflush(stdout)`, `ferror(stdout)`, or `fclose(stdout)` validation before returning from `main()`.

## Why This Is A Real Bug
The program’s sole purpose is to emit a valid joined gzip stream. If emission fails, successful completion is false. Returning `0` on a failed sink causes silent data loss, breaks pipelines, and misleads callers into accepting empty or truncated output as valid results. The reproduced closed-`stdout` case is a normal Unix failure mode, so this is reachable in practice.

## Fix Requirement
Every `stdout` write must be checked. Any short `fwrite()`, failed `putc()`, or final stream flush/error condition must terminate processing through the existing error path and return failure.

## Patch Rationale
The patch in `010-output-write-failures-are-silently-ignored.patch` hardens `examples/gzjoin.c` by validating each output operation and failing immediately on write errors. This converts silent truncation into an explicit error, preserves existing control flow expectations, and ensures `main()` no longer reports success when output delivery failed.

## Residual Risk
None

## Patch
`010-output-write-failures-are-silently-ignored.patch`