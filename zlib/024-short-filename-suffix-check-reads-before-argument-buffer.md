# Short filename suffix check reads before argument buffer

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `examples/gun.c:571`

## Summary
- In non-`-t` mode, `examples/gun.c` computes `len = strlen(*argv)` and performs suffix checks using `*argv + len - 3` and `*argv + len - 2` without first ensuring the filename is long enough.
- For short inputs such as `"a"`, these expressions point before the argument buffer, and `strcmp()`/suffix logic reads out of bounds during command-line parsing.

## Provenance
- Verified from the committed source in `examples/gun.c`
- Reproduced with AddressSanitizer using a one-character heap-backed argument
- Scanner origin: https://swival.dev

## Preconditions
- Program runs in non-`-t` mode
- A filename argument is shorter than the checked suffix length

## Proof
- At `examples/gun.c:571`, the code derives `len = strlen(*argv)`.
- The non-`-t` path then evaluates suffixes via `strcmp(*argv + len - 3, ".gz")` / `"-gz"` and later `*argv + len - 2`.
- With input `"a"`, `len == 1`, so `*argv + len - 3` becomes `*argv - 2`.
- `strcmp()` dereferences that invalid pointer before any file is opened, producing an out-of-bounds read.
- Reproduction with an ASan harness aborts with a `heap-buffer-overflow` in `strcmp`, originating from the `gun.c` suffix-check path; the reported read occurs 2 bytes before the `"a\0"` allocation, matching the `len - 3` underflow.

## Why This Is A Real Bug
- The failing path is reachable from normal command-line input with no special environment or corrupted state.
- The bug violates pointer bounds before any later validation or I/O can intervene.
- The ASan crash confirms concrete memory access outside the argument buffer, not a theoretical concern.

## Fix Requirement
- Guard suffix comparisons with explicit length checks, or use bounded suffix tests derived from `len`, so no pointer is formed before the start of the filename buffer.

## Patch Rationale
- The patch adds length validation before `.gz`, `-gz`, and related short-suffix checks.
- This preserves existing behavior for valid filenames while eliminating pointer underflow for short arguments.
- The change is localized to argument parsing and directly enforces the missing precondition required by the suffix logic.

## Residual Risk
- None

## Patch
- `024-short-filename-suffix-check-reads-before-argument-buffer.patch` adds bounded suffix handling in `examples/gun.c`, ensuring suffix pointers are only formed when `len` is at least the required suffix length.