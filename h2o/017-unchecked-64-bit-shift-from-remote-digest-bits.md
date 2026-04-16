# Unchecked remote digest bit-width permits 64-bit shift UB

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/http2/cache_digests.c:67`
- `lib/http2/cache_digests.c:99`
- `lib/http2/cache_digests.c:186`
- `lib/http2/hpack.c:601`
- `lib/http2/connection.c:1897`
- `lib/http2/stream.c:217`

## Summary
Remote `Cache-Digest` input is decoded into `nbits` and `pbits` without enforcing a safe shift domain before later bit operations. The original report identified the unsafe case as `nbits + pbits == 64`, but reproduction shows the reachable undefined behavior occurs when attacker-controlled input stores `capacity_bits == 0`, leading to a later `hash >> 64` in lookup. The patch closes the underlying validation gap by rejecting decoded digest widths outside the valid range before storing `capacity_bits` or using it in shifts.

## Provenance
- Source: verified finding and local reproduction against `lib/http2/cache_digests.c`
- Reachability confirmed through request parsing and server-push lookup flow
- Scanner reference: https://swival.dev

## Preconditions
- Attacker controls an HTTP/2 `Cache-Digest` request header
- The decoded digest frame yields an invalid bit width for later shift operations
- A subsequent cache-digest lookup path is reached during push eligibility checks

## Proof
- `h2o_hpack_parse_request` passes the remote `Cache-Digest` header to `h2o_cache_digests_load_header` via `lib/http2/hpack.c:601`
- `h2o_cache_digests_load_header` decodes attacker-controlled base64 and calls `load_digest`, which derives `nbits` and `pbits` into `frame.capacity_bits` in `lib/http2/cache_digests.c:67`
- Reproduction confirms a crafted header such as `Cache-Digest: AAA` can produce a stored frame with `capacity_bits == 0` at `lib/http2/cache_digests.c:99`
- Later, push-related lookup reaches `lookup`, which computes `uint64_t key = hash >> (64 - frame->capacity_bits);` at `lib/http2/cache_digests.c:186`
- With `capacity_bits == 0`, this becomes `hash >> 64`, which is undefined behavior for 64-bit `uint64_t`

## Why This Is A Real Bug
The bug is remotely reachable from request input, survives parsing into persistent digest state, and triggers undefined behavior in normal push-decision logic. Although the original report focused on the `== 64` case, the reproduced `== 0` case proves the same missing validation invariant is exploitable in practice: untrusted digest metadata is allowed to enter later shift expressions without bounds enforcement.

## Fix Requirement
Reject decoded digest widths that can make later shifts invalid. Enforce a strict valid range before assigning `capacity_bits` or performing any expression that depends on it.

## Patch Rationale
The patch adds input validation in `lib/http2/cache_digests.c` so decoded digest parameters are rejected unless they produce a safe, non-zero bit width below the machine word size. This directly restores the required shift-count invariant for both frame construction and later lookup operations, preventing remote input from reaching undefined bit shifts.

## Residual Risk
None

## Patch
- Patch file: `017-unchecked-64-bit-shift-from-remote-digest-bits.patch`
- Change: validate decoded digest bit counts before storing `capacity_bits`, rejecting invalid widths that would later cause undefined shifts in `lookup`
- Result: attacker-controlled `Cache-Digest` headers can no longer create frames with invalid shift operands such as `capacity_bits == 0` or widths exceeding the safe bound