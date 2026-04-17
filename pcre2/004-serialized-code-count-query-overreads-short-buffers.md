# Serialized code count query overreads short buffers

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/pcre2_serialize.c:246`

## Summary
`pcre2_serialize_get_number_of_codes()` accepts a raw pointer with no accompanying length and immediately reads serialized header fields from it. If a caller passes a non-NULL buffer shorter than `sizeof(pcre2_serialized_data)`, the function overreads the supplied bytes before it can return an error.

## Provenance
- Verified from source and reproduced with AddressSanitizer against the public API entrypoint
- Scanner: https://swival.dev

## Preconditions
- Caller passes a non-NULL undersized serialized buffer

## Proof
- `pcre2_serialize_get_number_of_codes()` casts `bytes` to `pcre2_serialized_data *` and reads `magic`, `version`, `config`, and `number_of_codes` during header validation without any size check.
- A PoC passed a 1-byte buffer positioned at the end of a readable page, with the following page mapped `PROT_NONE`.
- The call faults immediately during the first header access in `pcre2_serialize_get_number_of_codes_8`, before any `PCRE2_ERROR_*` result is returned.
- ASan stack trace identifies the crashing read in `src/pcre2_serialize.c:273`, reached from the PoC callsite.

## Why This Is A Real Bug
This is a reachable out-of-bounds read in a public API. Even if the API documentation expects a valid serialized stream, malformed or truncated inputs are not rejected safely because the function has no way to know the buffer length. In practice, this can crash the process or read adjacent memory while attempting header validation.

## Fix Requirement
The API must receive the serialized buffer length and reject inputs smaller than `sizeof(pcre2_serialized_data)` before dereferencing header fields.

## Patch Rationale
Adding a size parameter to the count-query API is the only complete fix because the current signature cannot distinguish a valid serialized buffer from a short one. The patched implementation should fail closed on undersized inputs before any header read, preserving existing validation for structurally invalid but sufficiently large buffers.

## Residual Risk
None

## Patch
- `004-serialized-code-count-query-overreads-short-buffers.patch` adds a serialized-length parameter to `pcre2_serialize_get_number_of_codes()`
- The implementation now checks for `NULL` and rejects buffers smaller than `sizeof(pcre2_serialized_data)` before accessing header fields
- Existing header validation remains in place for adequately sized inputs
- Callers must provide the actual serialized buffer size when querying the number of serialized codes