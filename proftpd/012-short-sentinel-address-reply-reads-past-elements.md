# Short Sentinel Address Reply Reads Past Elements

## Classification

Out-of-bounds read. Severity: high. Confidence: certain.

## Affected Locations

`src/redis.c:4304`

## Summary

`pr_redis_sentinel_get_master_addr` accepts any non-empty array reply from `SENTINEL get-master-addr-by-name`, then reads both `reply->element[0]` and `reply->element[1]`. A configured malicious or compromised Sentinel can return a one-element array, causing an out-of-bounds read and likely process termination during Redis master discovery.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

The server is configured to query an attacker-controlled Sentinel.

## Proof

Redis master discovery follows this path:

`pr_redis_conn_new` -> `discover_redis_master` -> `pr_redis_sentinel_get_master_addr`

In `pr_redis_sentinel_get_master_addr`, the code sends:

```c
SENTINEL get-master-addr-by-name <name>
```

The vulnerable branch accepts any array with at least one element:

```c
if (reply->elements > 0) {
  ...
  elt = reply->element[0];
  ...
  elt = reply->element[1];
```

A malicious Sentinel can return:

```text
["127.0.0.1"]
```

This satisfies `reply->elements > 0`, but `reply->element[1]` is outside the returned element array. The resulting pointer is immediately dereferenced through `elt->type`, so the process can crash during Redis master discovery.

## Why This Is A Real Bug

The expected Sentinel reply is a two-element `[host, port]` array. The implementation only checked for one or more elements before reading two elements. Because the reply originates from a configured Sentinel backend, a malicious or compromised Sentinel can control the array length and trigger the invalid read remotely within the stated trust boundary.

## Fix Requirement

Require `reply->elements >= 2` before reading `reply->element[1]`.

## Patch Rationale

The patch changes the array-length guard from `reply->elements > 0` to `reply->elements >= 2`. This matches the function's actual parsing requirement: both host and port elements must be present before either value can be safely used as a master address pair.

## Residual Risk

None

## Patch

```diff
diff --git a/src/redis.c b/src/redis.c
index 36277a43d..3a99376f3 100644
--- a/src/redis.c
+++ b/src/redis.c
@@ -5656,7 +5656,7 @@ int pr_redis_sentinel_get_master_addr(pool *p, pr_redis_t *redis,
     return -1;
   }
 
-  if (reply->elements > 0) {
+  if (reply->elements >= 2) {
     redisReply *elt;
     char *host = NULL;
     int port = -1;
```