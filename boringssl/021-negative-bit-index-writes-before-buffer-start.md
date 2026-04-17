# Negative bit index writes before buffer start

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `crypto/asn1/a_bitstr.cc:187`

## Summary
`ASN1_BIT_STRING_set_bit` accepts a signed bit index and does not reject negative values before deriving the byte offset. A negative `n` yields a negative `w = n / 8`, and execution can reach `a->data[w] = ...`, causing a write before the start of the allocated buffer.

## Provenance
- Verified from the supplied reproducer and source analysis
- Reference: https://swival.dev

## Preconditions
- Caller passes a negative bit index to `ASN1_BIT_STRING_set_bit`

## Proof
For `n = -8`, `w == -1` and `w + 1 == 0`. In `crypto/asn1/a_bitstr.cc`, the function can enter the allocation path when `a->data == nullptr`, perform a zero-size allocation, leave `a->length = 0`, and then execute `a->data[-1] = ...`. On non-empty bit strings, negative values at or below `-8` skip growth because `a->length < (w + 1)` is false for negative `w + 1`, then write directly through a negative index. This is a concrete out-of-bounds write reachable through the public API.

## Why This Is A Real Bug
The bug is memory corruption, not a theoretical arithmetic issue. The write lands before the user buffer in allocator-managed metadata. Subsequent allocator operations such as free or realloc may read that corrupted prefix, which can trigger sanitizer failures or destabilize heap behavior. The entrypoint is public and the invalid input is not filtered.

## Fix Requirement
Reject `n < 0` before computing the byte offset or touching `a->data`, and fail the operation without mutating the bit string.

## Patch Rationale
The patch adds an early validation check in `ASN1_BIT_STRING_set_bit` to return failure for negative bit indices. This is the narrowest correct fix because it blocks the invalid state before division, allocation sizing, length updates, or indexed writes occur.

## Residual Risk
None

## Patch
Patched in `021-negative-bit-index-writes-before-buffer-start.patch` by adding an early negative-index guard in `crypto/asn1/a_bitstr.cc` so `ASN1_BIT_STRING_set_bit` rejects `n < 0` before calculating `w` or accessing `a->data`.