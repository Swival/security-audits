# Full-body read lacks a decoded size cap

## Classification
- Type: vulnerability
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/body.rs:140`

## Summary
`Body::read_into_vec` fully buffers body data by repeatedly appending chunks into a `Vec` without enforcing any maximum accumulated size. When the body is attacker-controlled, this permits unbounded memory growth and denial of service. The impact is especially clear for gzip-decoded bodies because `poll_data` can emit arbitrarily large decompressed output before `read_into_vec` finishes buffering it.

## Provenance
- Verified from the provided report and reproduction notes
- Source review confirms the issue in `src/body.rs:140`
- Reference: https://swival.dev

## Preconditions
- Caller invokes a full-body read on attacker-controlled gzip or streaming body

## Proof
`Body::read_into_vec` loops over `body.data().await` and performs `bytes.extend_from_slice(&chunk)` for each yielded chunk, with no total-size guard in the accumulation path at `src/body.rs:140`.

The data source is attacker-reachable:
- `Chunk::CompressedHttpBody` is decoded in `poll_data`, which can yield large decompressed chunks
- `Chunk::Channel` can also stream arbitrary body data
- the nearby limit in `CollectingBody::tee(expected_length)` is cache-specific and does not constrain `Body::read_into_vec`
- `src/streaming_body.rs:10` documents a bound on chunk count, not byte size

This was reproduced with the supplied scenario: an attacker-controlled compressed response is auto-decompressed, then passed into a host path that calls the full-body read API, causing memory growth until allocation failure / OOM.

## Why This Is A Real Bug
This is not a theoretical resource issue; it is a direct missing bound on a hot buffering API. Any caller expecting `read_into_vec` to safely materialize a body can be forced to allocate attacker-chosen amounts of memory. Gzip makes exploitation easier because a small compressed payload can expand substantially after decoding, but the bug also affects other body sources that feed unbounded bytes into the same accumulation loop.

## Fix Requirement
Enforce a maximum accumulated decoded size in `read_into_vec` and return an error once the limit would be exceeded.

## Patch Rationale
The patch in `006-full-body-read-has-no-decompressed-size-limit.patch` adds a hard cap to the total bytes accumulated by `read_into_vec`. This places the protection at the full-buffering sink, which is the narrowest correct place to stop all oversized-body variants, including decompressed and streamed inputs, before memory exhaustion occurs.

## Residual Risk
None

## Patch
`006-full-body-read-has-no-decompressed-size-limit.patch`