# Short Sentinel Masters Entry Reads Past Elements

## Classification

Out-of-bounds read. Severity: high. Confidence: certain.

## Affected Locations

`src/redis.c:4415`

## Summary

`pr_redis_sentinel_get_masters()` parses `SENTINEL masters` replies without validating that each nested master array has at least two elements before reading `elt->element[1]`. A malicious or compromised configured Sentinel can return a RESP-valid but short nested array, causing an out-of-bounds hiredis element pointer read during Redis master discovery.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Redis Sentinel discovery is configured without an explicit master name, so `redis_sentinel_master == NULL` and master discovery calls `pr_redis_sentinel_get_masters()`.

## Proof

When `pr_redis_conn_new()` sees configured Sentinels, it queries them and calls `discover_redis_master()`. If no explicit Sentinel master name is configured, `discover_redis_master()` calls `pr_redis_sentinel_get_masters()`.

`pr_redis_sentinel_get_masters()` accepts any top-level `REDIS_REPLY_ARRAY` with elements, then iterates each nested entry:

```c
elt = reply->element[i];
if (elt->type == REDIS_REPLY_ARRAY) {
  redisReply *info;

  info = elt->element[1];
  *((char **) push_array(*masters)) = pstrndup(p, info->str, info->len);
}
```

A malicious Sentinel can return an outer array containing an empty nested array, RESP-equivalent to `[[]]`, or a one-element nested array. The parser reaches `info = elt->element[1]` even though the nested `elt->elements` count is less than two.

## Why This Is A Real Bug

The `SENTINEL masters` response is network-controlled by the configured Sentinel backend. The vulnerable parser validates the top-level reply type and non-emptiness, but not the per-master nested array length. RESP permits arrays with zero or one element, so the malformed reply is protocol-valid enough to reach the parser. Reading `elt->element[1]` when `elt->elements < 2` is memory-safety undefined behavior and can abort Redis master discovery or crash the process, causing denial of service.

## Fix Requirement

Require each nested `SENTINEL masters` array to contain at least two elements before reading `elt->element[1]`.

## Patch Rationale

The patch extends the existing nested-entry type check with a length check:

```c
if (elt->type == REDIS_REPLY_ARRAY &&
    elt->elements >= 2) {
```

This preserves existing behavior for well-formed Sentinel replies and skips malformed short entries before any indexed access occurs. The guarded read of `elt->element[1]` is now only reachable when that element exists.

## Residual Risk

None

## Patch

```diff
diff --git a/src/redis.c b/src/redis.c
index 36277a43d..2e1c12616 100644
--- a/src/redis.c
+++ b/src/redis.c
@@ -5783,7 +5783,8 @@ int pr_redis_sentinel_get_masters(pool *p, pr_redis_t *redis,
       redisReply *elt;
 
       elt = reply->element[i];
-      if (elt->type == REDIS_REPLY_ARRAY) {
+      if (elt->type == REDIS_REPLY_ARRAY &&
+          elt->elements >= 2) {
         redisReply *info;
 
         info = elt->element[1];
```