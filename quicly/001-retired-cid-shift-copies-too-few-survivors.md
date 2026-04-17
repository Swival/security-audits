# Retired CID shift copies too few survivors

## Classification
- Type: data integrity bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/remote_cid.c:140`

## Summary
`quicly_remote_cid_shift_retired` removes `count` retired connection IDs from the front of the queue, decrements `set->retired.count`, and then shifts survivors forward. The existing loop copies only `count` elements from `i + count` to `i`, which is insufficient whenever more than `count` entries survive. As a result, the surviving prefix is corrupted and later retirement retries can reference the wrong sequence numbers.

## Provenance
- Verified from the provided source and reproducer summary
- Scanner provenance: https://swival.dev

## Preconditions
- `retired.count > count` when shifting retired IDs

## Proof
The function takes caller-controlled `count` and performs a front-removal on `set->retired.cids`.
After decrementing `set->retired.count`, it currently copies only `count` entries:
```c
for (i = 0; i != count; ++i)
    set->retired.cids[i] = set->retired.cids[i + count];
```
If the old retired count is `N` and `0 < count < N - count`, then the new count is `N - count`, but only the first `count` survivors are moved. Survivors at original indexes `2 * count` through `N - 1` are never shifted into their new positions, leaving stale values in the active prefix.

This is reachable in normal queue management. Already-sent `RETIRE_CONNECTION_ID` frames are removed from the queue before acknowledgment and are only requeued on loss via `on_ack_retire_connection_id` in `lib/quicly.c:3587`. If `shift_retired` corrupts the survivor prefix, subsequent retries operate on incorrect sequence numbers.

## Why This Is A Real Bug
This is a concrete state-corruption bug, not a theoretical edge case. The function’s purpose is to preserve queue order after removing a prefix. Copying only `count` elements violates that contract whenever more than `count` entries remain. The resulting behavior can:
- resend retirements for sequence numbers already sent,
- drop retirements that were still pending,
- desynchronize local retirement state from intended protocol actions.

Peer-side duplicate retirements are ignored, but skipped retirements remain unsent, so local retirement progress can stall and consume queue capacity.

## Fix Requirement
Shift all surviving entries to the front after removing the first `count` retired IDs. The copy length must be the new retired count, or equivalently the old count minus `count`. `memmove` is acceptable because the source and destination ranges overlap.

## Patch Rationale
The patch changes the shift logic to move the full survivor range instead of only `count` elements. This preserves retired CID queue ordering and ensures all remaining pending retirements stay addressable for future send or retry paths.

## Residual Risk
None

## Patch
Patch file: `001-retired-cid-shift-copies-too-few-survivors.patch`

```diff
diff --git a/lib/remote_cid.c b/lib/remote_cid.c
index 0000000..0000000 100644
--- a/lib/remote_cid.c
+++ b/lib/remote_cid.c
@@ -140,8 +140,8 @@ void quicly_remote_cid_shift_retired(quicly_remote_cid_set_t *set, size_t count)
     assert(count <= set->retired.count);

     set->retired.count -= count;
-    for (size_t i = 0; i != count; ++i)
-        set->retired.cids[i] = set->retired.cids[i + count];
+    for (size_t i = 0; i != set->retired.count; ++i)
+        set->retired.cids[i] = set->retired.cids[i + count];
 }
```