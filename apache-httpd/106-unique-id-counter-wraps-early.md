# unique id counter wraps early

## Classification

Logic error, medium severity.

## Affected Locations

`modules/metadata/mod_unique_id.c:238`

## Summary

`mod_unique_id` encodes a two-byte request counter into `UNIQUE_ID`, but reduces the 32-bit counter with `% APR_UINT16_MAX`. Since `APR_UINT16_MAX` is `0xffff` / 65535, the encoded counter cycles after 65,535 values instead of covering the full 16-bit range of 65,536 values. Under the documented high-throughput condition, this permits duplicate `UNIQUE_ID` values within the same second for the same child/thread identity.

## Provenance

Verified from the provided source and reproducer evidence.

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The same child/thread handles 65,536 requests within one second.
- Each request reaches `set_unique_id` or `generate_log_id`.
- `stamp`, `root`, and `thread_index` remain unchanged across the colliding requests.

## Proof

`gen_unique_id` constructs `unique_id_rec` from stable fields plus a counter:

- `root` is copied from child state at `modules/metadata/mod_unique_id.c:219`.
- `stamp` is second-granularity from `apr_time_sec(r->request_time)` at `modules/metadata/mod_unique_id.c:220`.
- `thread_index` is derived from `r->connection->id` at `modules/metadata/mod_unique_id.c:221`.
- `counter` is incremented from `cur_unique_counter`.

The vulnerable line encodes:

```c
new_unique_id.counter = htons(counter % APR_UINT16_MAX);
```

Because `APR_UINT16_MAX` is `0xffff`, counters `N` and `N + 65535` encode to the same two-byte counter value. The value `0xffff` is never emitted. If the other fields are unchanged, the complete `unique_id_rec` and resulting encoded `UNIQUE_ID` are identical.

## Why This Is A Real Bug

The source comment states the counter is intended to “permit up to 64k requests in a single second by a single child.” A two-byte counter can represent 65,536 distinct values, but the implementation only emits 65,535 distinct values due to modulo `65535`.

This creates an actual duplicate-ID condition when the same child/thread processes 65,536 requests in one second with unchanged `stamp`, `root`, and `thread_index`.

## Fix Requirement

Use the full two-byte counter range by wrapping modulo `APR_UINT16_MAX + 1`, or equivalently by casting/truncating the 32-bit counter to 16 bits before converting to network byte order.

## Patch Rationale

The patch changes the modulus from 65,535 to 65,536:

```diff
-    new_unique_id.counter = htons(counter % APR_UINT16_MAX);
+    new_unique_id.counter = htons(counter % (APR_UINT16_MAX + 1));
```

This allows all 16-bit counter values from `0x0000` through `0xffff` to be emitted before wraparound. It preserves the existing encoded field size, byte order, data layout, and external `UNIQUE_ID` format.

## Residual Risk

None

## Patch

`106-unique-id-counter-wraps-early.patch`

```diff
diff --git a/modules/metadata/mod_unique_id.c b/modules/metadata/mod_unique_id.c
index 2555749..e1944ce 100644
--- a/modules/metadata/mod_unique_id.c
+++ b/modules/metadata/mod_unique_id.c
@@ -229,7 +229,7 @@ static const char *gen_unique_id(const request_rec *r)
     /* The counter is two bytes for the uuencoded unique id, in network
      * byte order.
      */
-    new_unique_id.counter = htons(counter % APR_UINT16_MAX);
+    new_unique_id.counter = htons(counter % (APR_UINT16_MAX + 1));
 
     /* we'll use a temporal buffer to avoid uuencoding the possible internal
      * paddings of the original structure */
```