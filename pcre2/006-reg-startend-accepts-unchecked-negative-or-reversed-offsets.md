# REG_STARTEND negative offsets reach out-of-bounds subject memory

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `src/pcre2posix.c:352`

## Summary
`pcre2_regexec()` accepts caller-controlled `pmatch[0]` offsets when `REG_STARTEND` is set and forwards them to `pcre2_match()` without validating that the start offset is non-negative and ordered. A negative `rm_so` shifts the subject pointer before the original buffer, causing an out-of-bounds read in the downstream matcher.

## Provenance
- Verified from the supplied finding and local reproduction evidence
- Reproducer used the POSIX API path in `pcre2_regexec()`
- Scanner source: https://swival.dev

## Preconditions
- Caller controls `pmatch[0]` with `REG_STARTEND` set

## Proof
- In `pcre2_regexec()`, `pmatch[0].rm_so` and `pmatch[0].rm_eo` are copied into signed `so` and `eo` without bounds checks.
- The function then calls `pcre2_match()` with subject pointer `(PCRE2_SPTR)string + so` and length `(eo - so)`.
- With `rm_so = -1` and `rm_eo = 3` on subject `"abc"`, the pointer passed to `pcre2_match()` points one byte before the stack buffer.
- Built with ASan/UBSan, this crashes in `pcre2_match_8` with a `stack-buffer-overflow` read, and the stack shows `pcre2_regexec -> pcre2_match_8`.
- Reversed offsets also remain unchecked in source and produce a wrapped `PCRE2_SIZE` length argument, though the supplied PoCs did not demonstrate a concrete memory violation for that variant.

## Why This Is A Real Bug
The negative-offset case is directly reachable through the public POSIX interface and causes the matcher to read from memory before the caller-provided subject buffer. This is memory-unsafe behavior, not a theoretical API misuse concern, and it is confirmed by sanitizer-backed reproduction.

## Fix Requirement
Reject invalid `REG_STARTEND` bounds before calling `pcre2_match()`, specifically negative `rm_so`, `rm_eo < rm_so`, and any oversized values that cannot be represented safely for the subject length calculation.

## Patch Rationale
The patch in `006-reg-startend-accepts-unchecked-negative-or-reversed-offsets.patch` adds input validation in the `REG_STARTEND` path so `pcre2_regexec()` fails early instead of constructing an underflowed subject pointer or wrapped match length. This preserves intended semantics for valid bounded searches while blocking the reproduced out-of-bounds read primitive.

## Residual Risk
None

## Patch
- `006-reg-startend-accepts-unchecked-negative-or-reversed-offsets.patch` validates `pmatch[0].rm_so` and `pmatch[0].rm_eo` before invoking `pcre2_match()`.
- The patch rejects negative starts, rejects reversed ranges, and rejects bounds that would overflow or exceed safe representable subject length handling.
- This prevents pointer underflow from `(PCRE2_SPTR)string + so` and prevents wrapped lengths from `(eo - so)` conversion.