# Short filename suffix check reads before argument buffer

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `examples/gun.c:571`
- `examples/gun.c:670`
- `examples/gun.c:673`

## Summary
In non-`-t` mode, `examples/gun.c` computes `len = strlen(*argv)` and then performs suffix checks using `*argv + len - 3` and `*argv + len - 2` without validating that the filename is at least 3 or 2 bytes long. For short filenames, these expressions point before the argument buffer and `strcmp()` performs an out-of-bounds read during command-line parsing.

## Provenance
- Reported from verified reproduction and patch development against the committed source
- External scanner reference: https://swival.dev

## Preconditions
- Program runs in non-`-t` mode
- A supplied filename is shorter than the checked suffix length

## Proof
A one-character filename is sufficient:
- Input: `"a"`
- Control flow enters the non-`-t` filename handling path
- `strlen("a") == 1`, so `*argv + len - 3` evaluates to `*argv - 2`
- `strcmp(*argv + len - 3, ".gz")` dereferences memory before the argument buffer
- ASan reproduction aborts with `AddressSanitizer: heap-buffer-overflow`, showing a read in `strcmp` originating from `gun.c:670`
- The report identifies the read as 2 bytes before the 2-byte `"a\0"` allocation, matching the `len - 3` underflow

## Why This Is A Real Bug
This path is reachable from ordinary command-line input, before any file is opened or validated. The underflowed pointer violates memory safety and causes undefined behavior. The failure is not theoretical: it is reproducible at runtime with ASan and directly follows from the committed pointer arithmetic.

## Fix Requirement
Guard suffix comparisons with explicit length checks, or use bounded suffix logic derived from `len` so no comparison starts before the beginning of the filename buffer.

## Patch Rationale
The patch updates suffix handling in `examples/gun.c` to require sufficient filename length before evaluating `.gz`, `-gz`, or `.z`-style tail checks. This preserves existing behavior for valid compressed filenames while eliminating pointer underflow for short arguments.

## Residual Risk
None

## Patch
- Patch file: `024-short-filename-suffix-check-reads-before-argument-buffer.patch`
- Patched file: `examples/gun.c`