# Output write failures return success

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `examples/gzjoin.c:229`
- `examples/gzjoin.c`
- Patch: `010-output-write-failures-are-silently-ignored.patch`

## Summary
`gzjoin` emits gzip output to `stdout` via `fwrite()` and `putc()` but does not check write results. When `stdout` is closed, full, or otherwise failing, output generation truncates or produces no data while the program continues processing and exits with status 0.

## Provenance
- Verified from the provided reproduction and source inspection in `examples/gzjoin.c`
- Scanner source: https://swival.dev

## Preconditions
- `stdout` write fails during output generation

## Proof
The reproduced case closes fd 1 before invoking the tool:
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

This matches the source behavior:
- output bytes are written with unchecked `fwrite()` and `putc()` calls in `gzinit()`, `gzcopy()`, and `put4()`
- `main()` returns success after processing without checking `fflush(stdout)`, `ferror(stdout)`, or `fclose(stdout)`
- therefore a write-failure path is reachable and silently reported as success

## Why This Is A Real Bug
A failing output sink is a normal operational error, not a theoretical edge case. Closed pipes, broken pipelines, disk-full redirections, and permission or device errors all cause `stdout` writes to fail. In this program, those failures directly invalidate the produced gzip stream, yet callers receive a success exit code. That breaks shell scripting, automation, and any workflow relying on exit status to detect truncated output.

## Fix Requirement
Every `stdout` write must be checked. Any short `fwrite()` or `EOF` from `putc()` must terminate processing as an error, and final stream state must be validated before returning success.

## Patch Rationale
The patch should centralize or consistently apply checked output helpers in `examples/gzjoin.c` so that:
- each `fwrite()` verifies the full byte count was written
- each `putc()` verifies it did not return `EOF`
- write failure forces an error path instead of continued processing
- final `stdout` flush/state is checked before returning success

This directly closes the reproduced path and aligns exit status with actual output integrity.

## Residual Risk
None

## Patch
`010-output-write-failures-are-silently-ignored.patch` updates `examples/gzjoin.c` to treat `stdout` write failures as fatal by checking all output operations and propagating an error instead of silently succeeding.