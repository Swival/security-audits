# Peer Metric Bandwidth Divides By Zero

## Classification

Denial of service, high severity. Confidence: certain.

## Affected Locations

`usr.sbin/eigrpd/rde_dual.c:359`

## Summary

An established EIGRP neighbor can advertise a route metric with `bandwidth = 0`. The RDE route decision path copies that peer-controlled metric and later calls `eigrp_real_bandwidth()`, which divides by the bandwidth value. A zero value therefore deterministically reaches an integer divide-by-zero and can terminate `eigrpd` on platforms where this traps.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

An established EIGRP neighbor can advertise route metrics.

## Proof

`rde_check_update()`, `rde_check_query()`, and `rde_check_reply()` process neighbor-supplied `struct rinfo` values and call `route_new()` or `route_update_metrics()` without validating `ri->metric.bandwidth`.

`route_update_metrics()` copies the attacker-controlled metric:

```c
route->metric = ri->metric;
```

It then immediately computes real bandwidth from the copied metric:

```c
bandwidth = eigrp_real_bandwidth(route->metric.bandwidth);
```

`eigrp_real_bandwidth()` performs division by the supplied value:

```c
return ((EIGRP_SCALING_FACTOR * (uint32_t)10000000) / bandwidth);
```

A malicious neighbor advertising `bandwidth = 0` therefore causes a divide-by-zero before later route filtering or metric handling can reject the route.

The reproduced paths include update handling, query handling, and reply handling under normal active-route/outstanding-reply conditions.

## Why This Is A Real Bug

The input is peer-controlled after neighbor establishment, and no validation blocks zero bandwidth before the arithmetic sink. Integer division by zero is undefined behavior in C and commonly raises `SIGFPE`; the RDE process installs no `SIGFPE` handler. This makes the failure a remotely triggerable denial of service by an authenticated or established routing peer.

## Fix Requirement

Prevent zero bandwidth from reaching any bandwidth conversion division. The fix must either reject the metric or clamp zero to a safe minimum before division.

## Patch Rationale

The patch adds a guard in `eigrp_real_bandwidth()`, the confirmed division sink. Returning `MIN_BANDWIDTH` for zero avoids the crash and centralizes protection for callers that convert composite bandwidth back to real bandwidth.

This is a minimal, targeted fix: it preserves existing behavior for all non-zero bandwidth values and prevents the deterministic divide-by-zero for malformed peer metrics.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/eigrpd/rde_dual.c b/usr.sbin/eigrpd/rde_dual.c
index e12bf38..beb0022 100644
--- a/usr.sbin/eigrpd/rde_dual.c
+++ b/usr.sbin/eigrpd/rde_dual.c
@@ -357,6 +357,9 @@ eigrp_real_bandwidth(uint32_t bandwidth)
 	 * apply the scaling factor before the division and only then truncate.
 	 * this is to keep consistent with what cisco does.
 	 */
+	if (bandwidth == 0)
+		return (MIN_BANDWIDTH);
+
 	return ((EIGRP_SCALING_FACTOR * (uint32_t)10000000) / bandwidth);
 }
```