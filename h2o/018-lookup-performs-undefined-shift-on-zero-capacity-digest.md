# Lookup undefined shift on zero-capacity digest

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/http2/cache_digests.c:90`
- `lib/http2/cache_digests.c:132`
- `lib/http2/cache_digests.c:186`
- `lib/http2/hpack.c:601`
- `lib/http2/connection.c:625`
- `lib/http2/connection.c:1900`
- `lib/http2/stream.c:223`

## Summary
`h2o_cache_digests_load_header` accepts attacker-controlled `Cache-Digest` input and `load_digest` stores frames where decoded `nbits` and `pbits` are both zero, making `capacity_bits == 0`. A later lookup right-shifts a 64-bit hash by `64 - frame->capacity_bits`, which becomes `64` for such a frame. Shifting a `uint64_t` by 64 is undefined behavior and is reachable through normal HTTP/2 request handling.

## Provenance
- Reproduced from the verified finding and UBSan report provided by the reporter
- Scanner source: https://swival.dev

## Preconditions
- An attacker supplies a `Cache-Digest` header whose decoded 5-bit `nbits` and `pbits` fields are both zero
- The server later evaluates that stored digest during a push-related cache-digest lookup path

## Proof
- `h2o_cache_digests_load_header` passes header data into `load_digest`, which computes `frame.capacity_bits = nbits + pbits` without rejecting zero and appends the frame at `lib/http2/cache_digests.c:90`
- HTTP/2 header parsing makes this attacker reachable via `lib/http2/hpack.c:601`, and the parsed digest is stored on the stream at `lib/http2/connection.c:625`
- Later push decision paths call `h2o_cache_digests_lookup_by_url` / `h2o_cache_digests_lookup_by_url_and_etag` from `lib/http2/connection.c:1900` and `lib/http2/stream.c:223`
- `lookup` performs `hash >> (64 - frame->capacity_bits)` at `lib/http2/cache_digests.c:186`; with `capacity_bits == 0`, this becomes `hash >> 64`
- UBSan confirms the runtime fault on a minimal PoC using `h2o_cache_digests_load_header(&digests, "AAA", 3);` followed by lookup: `lib/http2/cache_digests.c:186:33: runtime error: shift exponent 64 is too large for 64-bit type 'uint64_t'`

## Why This Is A Real Bug
The invalid state is accepted from network input, persisted, and consumed by a later reachable code path. The resulting shift count exceeds the language-defined range for `uint64_t`, so behavior is undefined in C. This is not a theoretical edge case: the reporter reproduced it with sanitizer instrumentation on attacker-controlled input along a normal HTTP/2 request-to-lookup flow.

## Fix Requirement
Reject cache-digest frames with `capacity_bits == 0` before storing them, or otherwise guarantee lookup never executes a 64-bit shift on zero capacity.

## Patch Rationale
The patch should enforce the digest invariant at parse time in `lib/http2/cache_digests.c` by treating zero-capacity frames as invalid and refusing to append them. That removes the attacker-controlled invalid state at its source and prevents downstream lookup from ever reaching the undefined shift.

## Residual Risk
None

## Patch
- `018-lookup-performs-undefined-shift-on-zero-capacity-digest.patch` rejects zero-capacity digest frames in `lib/http2/cache_digests.c` before they are stored, ensuring later lookup code cannot execute `hash >> 64` on attacker-supplied input.