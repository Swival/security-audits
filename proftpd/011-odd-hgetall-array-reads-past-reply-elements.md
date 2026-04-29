# Odd HGETALL Array Reads Past Reply Elements

## Classification

High severity out-of-bounds read.

Confidence: certain.

## Affected Locations

`src/redis.c:3183`

## Summary

`pr_redis_hash_kgetall()` parses an `HGETALL` array reply as alternating key/value elements but did not validate that `reply->elements` is even. An odd-length array causes the final loop iteration to read `reply->element[i+1]` one entry past the returned element array, then dereference it via `value_elt->type`. A malicious Redis-compatible backend can trigger an FTP worker crash.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- ProFTPD is built with Redis support.
- ProFTPD uses Redis and calls `pr_redis_hash_kgetall()`.
- The Redis backend, proxy, or compatible service can return a crafted odd-length `HGETALL` array reply.

## Proof

`pr_redis_hash_kgetall()` sends `HGETALL`, accepts any `REDIS_REPLY_ARRAY`, and checks only that `reply->elements > 0` before pair parsing.

The vulnerable loop advances by two elements:

```c
for (i = 0; i < reply->elements; i += 2) {
  key_elt = reply->element[i];
  ...
  value_elt = reply->element[i+1];
  if (value_elt->type == REDIS_REPLY_STRING) {
```

For an odd `reply->elements` value, the last iteration has `i == reply->elements - 1`. `reply->element[i]` is in bounds, but `reply->element[i+1]` reads one pointer past the allocated element array. The next access, `value_elt->type`, dereferences that out-of-bounds pointer and provides a concrete crash path.

hiredis exposes RESP arrays as returned and does not enforce Redis command-level `HGETALL` key/value pairing semantics for a malicious or non-conforming backend.

## Why This Is A Real Bug

The parser trusts backend reply shape beyond the RESP type. `HGETALL` semantics require key/value pairs, but RESP itself permits arrays with arbitrary lengths. Because the code indexes `i+1` without first proving that it exists, an attacker-controlled odd array length directly reaches an out-of-bounds pointer read and dereference in the FTP worker process.

## Fix Requirement

Reject odd `HGETALL` array replies before entering the key/value pair loop, or otherwise guard every `i+1` access.

## Patch Rationale

The patch adds an explicit even-element validation immediately after confirming `reply->type == REDIS_REPLY_ARRAY` and before any pair iteration. Odd-length replies are treated as malformed, logged, freed, and returned with `EINVAL`. This preserves normal handling for valid empty arrays and valid key/value pair arrays while eliminating the unchecked `i+1` access.

## Residual Risk

None

## Patch

```diff
diff --git a/src/redis.c b/src/redis.c
index 36277a43d..8e392dcc0 100644
--- a/src/redis.c
+++ b/src/redis.c
@@ -3051,6 +3051,16 @@ int pr_redis_hash_kgetall(pool *p, pr_redis_t *redis, module *m,
     return -1;
   }
 
+  if ((reply->elements % 2) != 0) {
+    pr_trace_msg(trace_channel, 2,
+      "expected even number of elements for %s, got %lu", cmd,
+      (unsigned long) reply->elements);
+    freeReplyObject(reply);
+    destroy_pool(tmp_pool);
+    errno = EINVAL;
+    return -1;
+  }
+
   if (reply->elements > 0) {
     register unsigned int i;
```