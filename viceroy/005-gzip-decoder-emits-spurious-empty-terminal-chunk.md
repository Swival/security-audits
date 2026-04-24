# Gzip decoder emits spurious empty terminal chunk

## Classification
- Type: data integrity bug
- Severity: low
- Confidence: certain

## Affected Locations
- `src/body.rs:238`

## Summary
`Body::poll_data` always emitted a final `Some(Ok(Bytes::new()))` after `GzDecoder::try_finish()` for `Chunk::CompressedHttpBody`, even when decompression had already produced all output. This added a spurious terminal data chunk to otherwise complete gzip streams.

## Provenance
- Source: verified finding reproduced from the committed codebase
- Scanner: https://swival.dev

## Preconditions
- A gzip-wrapped body reaches end-of-stream after all decompressed output was already emitted

## Proof
- `Chunk::compressed_body(hyper::Body)` routes compressed upstream bodies through `Body::poll_data`.
- In the `Chunk::CompressedHttpBody` branch, each compressed input chunk is written into `GzDecoder`, then pending output is returned from the internal buffer.
- When the inner body later returns `Poll::Ready(None)`, the code calls `try_finish()` and then unconditionally returns `Some(Ok(split().freeze()))` at `src/body.rs:238`.
- If `try_finish()` produces no additional bytes, `split().freeze()` is empty, so the stream yields an extra zero-length `Bytes` item instead of terminating.
- Reproduction confirmed this with a temporary `cargo test -q -p viceroy-lib --test verify_gzip_empty -- --nocapture` using `gzip("hello world")`: iteration over `body.data().await` produced the payload chunk followed by a final empty chunk.

## Why This Is A Real Bug
This is reachable in normal operation because transparent upstream decompression wraps gzip responses in `src/upstream.rs:374` and `src/upstream.rs:381`. While full-body collectors still reconstruct correct bytes, direct `HttpBody` consumers observe an invalid extra data event, changing stream framing and chunk sequencing. That behavior is externally visible to streaming consumers and tests.

## Fix Requirement
After `try_finish()`, return `Poll::Ready(None)` when the split output buffer is empty; only emit a final data chunk if finishing the decoder actually produced bytes.

## Patch Rationale
The fix makes terminal behavior match body-stream semantics: data events are emitted only for real payload bytes, and stream completion is represented by `None`. This preserves all decompressed content while removing the spurious empty terminal chunk.

## Residual Risk
None

## Patch
Patched in `005-gzip-decoder-emits-spurious-empty-terminal-chunk.patch`. The change updates `src/body.rs` so the gzip decoder finish path checks whether the drained buffer is empty before returning a terminal chunk; empty output now ends the stream with `Poll::Ready(None)`.