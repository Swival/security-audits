# Port ivar truncates silently to 16 bits

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/handler/mruby/redis.c:118`

## Summary
`connect_method` reads Ruby `@port` and narrows it to `uint16_t` without validating range. Out-of-range integers wrap modulo 16 bits before the Redis connection call, causing connection attempts to an unintended port.

## Provenance
- Verified from source and reproducer details
- Scanner provenance: https://swival.dev

## Preconditions
- Ruby sets `@port` outside `0..65535` before `__connect`

## Proof
- `connect_method` reads `@port` with `mrb_fixnum(_port)` and stores it in a `uint16_t` at `lib/handler/mruby/redis.c:118`
- `mrb_fixnum` returns an `mrb_int` directly, with no bounds enforcement in mruby boxing helpers
- Narrowing to `uint16_t` wraps modulo `2^16`; examples confirmed by type semantics:
  - `70000` -> `4464`
  - `65536` -> `0`
  - `-1` -> `65535`
- The wrapped value is used by `h2o_redis_connect(&client->super, host, port)` at `lib/handler/mruby/redis.c:147`
- `h2o_redis_connect` accepts `uint16_t port` at `include/h2o/redis.h:74` and passes it through to hiredis in `lib/common/redis.c:141` and `lib/common/redis.c:147`

## Why This Is A Real Bug
The code performs the actual outbound connection using the truncated port value, so invalid Ruby input changes runtime behavior in a predictable, reachable way. This is not theoretical: negative or oversized integers deterministically map to a different TCP port and can redirect Redis connection attempts away from the intended destination.

## Fix Requirement
Validate that `@port` is an integer within `0..65535` before casting to `uint16_t`; raise an exception on invalid values.

## Patch Rationale
The patch in `027-port-ivar-truncates-silently-to-16-bits.patch` adds explicit range validation before the narrowing conversion. This preserves valid behavior for legitimate ports and fails closed for malformed input, preventing silent wraparound and unintended connections.

## Residual Risk
None

## Patch
`027-port-ivar-truncates-silently-to-16-bits.patch`