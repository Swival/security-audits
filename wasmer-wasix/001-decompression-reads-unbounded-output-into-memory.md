# Decompression output cap added

## Classification
Medium severity vulnerability; certain confidence; memory exhaustion denial of service via unbounded decompression of remotely supplied package bodies.

## Affected Locations
- `lib/wasix/src/runtime/package_loader/builtin_loader.rs:314`
- `lib/wasix/src/runtime/package_loader/builtin_loader.rs:376`
- `lib/wasix/src/runtime/package_loader/builtin_loader.rs:402`

## Summary
`download()` accepts attacker-controlled compressed package responses, passes `response.body` into `decode_response_body()`, and that function previously decompressed with `read_to_end()` into an unbounded `Vec`. A small gzip or zstd payload could therefore expand until the process exhausted memory before hash validation or package parsing. The patch enforces a maximum decoded-size limit during streaming decompression and fails once the limit is exceeded.

## Provenance
Reproduced from the verified finding and source analysis in `lib/wasix/src/runtime/package_loader/builtin_loader.rs`. Scanner reference: https://swival.dev

## Preconditions
A remote package server returns a compressed response and sets `Content-Encoding` so the builtin loader enters the decompression path.

## Proof
The vulnerable path is direct and unconditional for non-`file://` downloads with content encoding:
- `download()` reads the full HTTP body from `HttpClient` and calls `decode_response_body()` before integrity validation in `lib/wasix/src/runtime/package_loader/builtin_loader.rs:312` and `lib/wasix/src/runtime/package_loader/builtin_loader.rs:314`.
- `decode_response_body()` constructs gzip/zstd decoders and previously called `reader.read_to_end(&mut decoded)` on a fresh `Vec` with no decoded-size bound in `lib/wasix/src/runtime/package_loader/builtin_loader.rs:376` and `lib/wasix/src/runtime/package_loader/builtin_loader.rs:402`.
- Because validation occurs only after decompression completes, a malicious compressed body can force arbitrary heap growth even if the hash later fails.

## Why This Is A Real Bug
This is a reachable remote memory DoS in normal package download flow. The attacker controls both compressed bytes and expansion ratio, while the code allocated decoded output without limit. Since the body is decompressed before hash verification, integrity checks do not mitigate the allocation impact. Process termination by OOM or allocator failure is a realistic outcome.

## Fix Requirement
Bound decoded output size during decompression and return an error as soon as the decoded stream exceeds the configured maximum.

## Patch Rationale
The patch changes decompression to enforce a hard decoded-byte ceiling while streaming gzip/zstd output, preventing attacker-controlled expansion from consuming unbounded memory. This preserves existing behavior for legitimate packages within the limit and aborts the request before hash validation when the decompressed payload is too large.

## Residual Risk
None

## Patch
Patch file: `001-decompression-reads-unbounded-output-into-memory.patch`