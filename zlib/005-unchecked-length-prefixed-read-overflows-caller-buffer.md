# Unchecked length-prefixed read overflows caller buffer

## Classification
- Type: vulnerability
- Severity: high
- Confidence: certain

## Affected Locations
- `contrib/iostream2/zstream.h:120`

## Summary
`operator>(izstream&, char*)` reads an archive-controlled length, copies that many bytes into a caller-provided buffer, and then appends a NUL terminator without any buffer-size check. A crafted stream can therefore trigger out-of-bounds writes when the caller buffer is smaller than `len.value() + 1`.

## Provenance
- Verified by reproduction against the repository code
- Scanner reference: https://swival.dev

## Preconditions
- Caller uses `operator>(izstream&, char*)` with a buffer smaller than the encoded length.
- Compressed input is attacker-controlled or otherwise untrusted.

## Proof
- `zstringlen(izstream&)` derives the string length directly from archive bytes in `contrib/iostream2/zstream.h:128`.
- `operator>(izstream&, char*)` then performs `gzread(zs.fp(), x, len.value())` and writes `x[len.value()] = '\0'` in `contrib/iostream2/zstream.h:120`.
- The API takes only `char *x`; it receives no destination capacity and performs no bounds validation.
- The repository example uses fixed-size buffers in `contrib/iostream2/zstream_test.cpp:14` and calls the unsafe overload in `contrib/iostream2/zstream_test.cpp:15`, so an encoded length above 255 overflows those buffers.

## Why This Is A Real Bug
The overflow is directly controlled by serialized input, not by an internal invariant. The function cannot validate safety because its signature omits buffer length, making misuse unavoidable for callers that cannot guarantee trusted lengths. The bug is reachable with crafted archive data and causes concrete out-of-bounds writes during both the read and terminator store.

## Fix Requirement
Replace the unsafe `char*` extraction overload with a size-checked API that accepts destination capacity and rejects encoded lengths that do not fit, including space for the terminating NUL.

## Patch Rationale
The patch removes the unchecked read path by introducing a bounded interface for C-string extraction, validating `len.value() < capacity` before reading, and failing safely when the encoded length exceeds the caller buffer. This closes both the bulk-copy overflow and the trailing terminator overwrite at the vulnerable call site in `contrib/iostream2/zstream.h`.

## Residual Risk
None

## Patch
- Patch file: `005-unchecked-length-prefixed-read-overflows-caller-buffer.patch`
- The patch implements a size-aware replacement for the `char*` overload in `contrib/iostream2/zstream.h` and rejects oversized length-prefixed inputs before any write occurs.