# Negative Ready Inflates Slot Total

## Classification

Data integrity bug; severity medium; confidence certain.

## Affected Locations

`modules/proxy/balancers/mod_lbmethod_heartbeat.c:315`

## Summary

Heartbeat load balancing accepts negative `ready` values from heartbeat records and adds them to unsigned slot accounting. A negative `ready` value is converted to a large unsigned value, inflating `openslots` and corrupting weighted worker selection.

## Provenance

Verified and reproduced from scanner output attributed to Swival Security Scanner: https://swival.dev

## Preconditions

- Heartbeat data contains a worker matching a configured balancer worker.
- The heartbeat record has a recent `lastseen` value.
- The heartbeat record contains a negative `ready` value.
- Heartbeat load balancing reads the malformed value from either heartbeat file data or slotmem heartbeat records.

## Proof

`readfile_heartbeats` parses `ready` using `atoi`, allowing negative integers.

`hm_read` copies `slotserver->ready` into `server->ready` without validation.

`find_best_hb` then adds signed `server->ready` into unsigned `apr_uint32_t openslots`:

```c
openslots += server->ready;
```

With `openslots == 0` and `server->ready == -1`, the addition converts `-1` to `0xffffffff`, making `openslots == 4294967295`.

The inflated value is then used by:

```c
pick = ap_random_pick(0, openslots);
```

The later selection comparison also mixes unsigned `c` with negative `server->ready`, allowing a negative-capacity worker to dominate or corrupt selection behavior.

## Why This Is A Real Bug

A worker advertising negative available capacity should never increase the available slot total or participate as a viable destination. Because the current code performs arithmetic between signed negative capacity and an unsigned accumulator, malformed heartbeat data can make unavailable capacity appear as a very large positive capacity.

This directly affects runtime load balancing decisions and can route traffic to an invalid or maliciously favored worker.

## Fix Requirement

Reject negative `ready` values before adding them to `openslots` or including the server in the candidate array.

## Patch Rationale

The patch updates the freshness check in `find_best_hb` so only non-negative `ready` values are counted:

```diff
-            if (server->seen < LBM_HEARTBEAT_MAX_LASTSEEN) {
+            if (server->seen < LBM_HEARTBEAT_MAX_LASTSEEN && server->ready >= 0) {
```

This prevents negative signed values from being converted during unsigned addition and excludes invalid negative-capacity workers from weighted selection.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/proxy/balancers/mod_lbmethod_heartbeat.c b/modules/proxy/balancers/mod_lbmethod_heartbeat.c
index 0534e5b..58f5fc0 100644
--- a/modules/proxy/balancers/mod_lbmethod_heartbeat.c
+++ b/modules/proxy/balancers/mod_lbmethod_heartbeat.c
@@ -311,7 +311,7 @@ static proxy_worker *find_best_hb(proxy_balancer *balancer,
 
         if (PROXY_WORKER_IS_USABLE(*worker)) {
             server->worker = *worker;
-            if (server->seen < LBM_HEARTBEAT_MAX_LASTSEEN) {
+            if (server->seen < LBM_HEARTBEAT_MAX_LASTSEEN && server->ready >= 0) {
                 openslots += server->ready;
                 APR_ARRAY_PUSH(up_servers, hb_server_t *) = server;
             }
```