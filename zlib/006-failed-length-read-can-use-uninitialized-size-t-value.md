# Failed length read can use uninitialized `size_t` value

## Classification
- Type: error-handling bug
- Severity: high
- Confidence: certain

## Affected Locations
- `contrib/iostream2/zstream.h:112`
- `contrib/iostream2/zstream.h:137`

## Summary
Truncated attacker-controlled gzip input can cause `gzread` to return fewer bytes than requested while the code still consumes the destination objects as fully initialized. In the encoded-length path, this permits a partially uninitialized `size_t` to flow into string allocation and indexing.

## Provenance
- Verified from the provided reproducer and code inspection in the local worktree
- Reference: Swival Security Scanner, `https://swival.dev`

## Preconditions
- Attacker controls compressed input and can truncate the encoded string length field.

## Proof
`operator>(izstream&, T&)` reads with `gzread` and ignores the returned byte count. In `zstringlen(izstream&)`, the code first reads `val.byte`; if that byte is `255`, it then reads `val.word` using `sizeof(size_t)` bytes without checking that all bytes were delivered. On truncated input, `val.word` remains partially uninitialized.

That indeterminate value is then used by `read_string()` to allocate `new char[len.value()+1]`, and by `operator>(izstream&, char*)` to read `len.value()` bytes and write `x[len.value()] = '\0'`. The reproducer confirmed this propagation with a gzip payload containing `0xff` followed by only two bytes: `gzread(..., &word, sizeof(word))` returned `2` on an 8-byte `size_t`, leaving the remaining bytes untouched.

## Why This Is A Real Bug
This is reachable on attacker-supplied `.gz` input through the public deserialization path and does not rely on undefined control flow alone; the truncated read concretely leaves stale bytes in `size_t`, and that value directly controls allocation size, read size, and buffer indexing. The result is a practical memory-safety and denial-of-service failure mode.

## Fix Requirement
Every `gzread` involved in deserialization must be checked for an exact-length read before the destination value is used. Short reads in the length-decoding path must fail closed rather than interpreting partially initialized data as a valid length.

## Patch Rationale
The patch in `006-failed-length-read-can-use-uninitialized-size-t-value.patch` enforces exact byte-count validation for length-field reads before `val.byte` or `val.word` are consumed. This removes the uninitialized `size_t` path and ensures truncated gzip input is treated as an error instead of a valid serialized string length.

## Residual Risk
None

## Patch
- `006-failed-length-read-can-use-uninitialized-size-t-value.patch` validates `gzread` results for the encoded string length reads in `contrib/iostream2/zstream.h`, preventing partially initialized length values from reaching allocation and indexing sites.