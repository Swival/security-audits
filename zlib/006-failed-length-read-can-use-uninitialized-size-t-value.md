# Failed length read can use uninitialized size_t value

## Classification
- Type: error-handling bug
- Severity: high
- Confidence: certain

## Affected Locations
- `contrib/iostream2/zstream.h:112`
- `contrib/iostream2/zstream.h:137`

## Summary
A truncated gzip stream can cause `zstringlen(izstream&)` to consume a partially unread `size_t` length because `gzread` results are ignored. The resulting indeterminate length is then used by `read_string()` for allocation and by `operator>(izstream&, char*)` for indexing and reads.

## Provenance
- Verified from the provided finding and reproducer
- Reproduced against the local code path handling attacker-controlled `.gz` input
- Scanner reference: https://swival.dev

## Preconditions
- Attacker controls compressed input and can truncate the encoded string length field.

## Proof
- `operator>(izstream&, T&)` reads from `gzread` but does not require an exact byte count before returning.
- In `zstringlen(izstream&)`, `zs > val.byte; if (val.byte == 255) zs > val.word;` allows `val.word` to remain partially uninitialized on short read.
- `read_string()` uses `len.value()` in `new char[len.value()+1]`.
- `operator>(izstream&, char*)` uses `x[len.value()] = '\0'` after reading based on the same unchecked length.
- Reproduction confirmed `gzread(..., &word, sizeof(word))` can return a short count on truncated gzip input while leaving unread bytes unchanged, preserving stale stack data in `word`.

## Why This Is A Real Bug
This is reachable through the intended deserialization interface for gzip-backed input. On truncation after the `255` sentinel, the code trusts an indeterminate `size_t` as a validated string length. That can trigger oversized allocation attempts, oversized reads, and out-of-bounds writes relative to the caller’s actual buffer assumptions. The failure is not theoretical; it follows directly from documented `gzread` short-read behavior and was reproduced.

## Fix Requirement
Require every `gzread` used for scalar length decoding to return the exact requested byte count before the value is used. Abort deserialization on mismatch and do not consume `val.byte`, `val.word`, or derived string lengths after a short read.

## Patch Rationale
The patch in `006-failed-length-read-can-use-uninitialized-size-t-value.patch` adds exact-length checks to the gzip read path before length fields are trusted. This removes the uninitialized-length propagation at its source and prevents `read_string()` and `operator>(izstream&, char*)` from allocating, reading, or indexing with indeterminate sizes.

## Residual Risk
None

## Patch
- `006-failed-length-read-can-use-uninitialized-size-t-value.patch` validates `gzread` return values for byte and `size_t` length reads before use.
- The patch ensures truncated encoded lengths fail closed instead of flowing into allocation and string read operations.
