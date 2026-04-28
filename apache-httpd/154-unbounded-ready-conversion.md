# Unbounded Ready Conversion

## Classification

Validation gap, low severity. Confidence: certain.

## Affected Locations

`modules/proxy/balancers/mod_lbmethod_heartbeat.c:187`

## Summary

`readfile_heartbeats()` parsed the `ready` heartbeat parameter with `atoi()` without validating range. If heartbeat storage contains a numeric `ready` value outside the representable range of `int`, `atoi()` has undefined behavior. The patch replaces the conversion with bounded `strtol()` parsing and only assigns values within `INT_MIN` through `INT_MAX`.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

- Heartbeat load balancing is configured and reads from file-backed `HeartbeatStorage`.
- `mod_heartmonitor` slotmem is not attached, so `read_heartbeats()` uses `readfile_heartbeats()`.
- The heartbeat storage file contains an out-of-range `ready` parameter.

## Proof

`readfile_heartbeats()` reads heartbeat storage lines and parses the query string with `argstr_to_table()`. That helper URL-decodes keys and values, then stores them unchanged in an APR table.

When a `ready` key is present, the original code executed:

```c
server->ready = atoi(val);
```

For numeric input not representable as `int`, POSIX specifies undefined behavior for `atoi()`. This path is reachable whenever configured file-backed `HeartbeatStorage` is read during heartbeat balancer selection.

The reproduced path confirmed:

- `argstr_to_table()` stores query values unchanged apart from URL decoding.
- `ready` flows from the heartbeat file into `atoi()`.
- The resulting `server->ready` can later contribute to open-slot accounting in `find_best_hb()`.

## Why This Is A Real Bug

This is not a theoretical unreachable conversion. The heartbeat file is explicitly read by `readfile_heartbeats()` when slotmem is unavailable, and `ready` is attacker- or environment-controlled to the extent that heartbeat storage contents can be influenced. Passing an out-of-range numeric string to `atoi()` invokes undefined behavior before any later balancing logic can safely reason about the value.

## Fix Requirement

Parse `ready` with a bounded numeric conversion such as `strtol()` or `apr_strtoi64()`, detect range errors, and reject values outside the target `int` range before assigning to `server->ready`.

## Patch Rationale

The patch adds `<errno.h>` and `<limits.h>`, then replaces `atoi(val)` for `ready` with:

```c
errno = 0;
ready = strtol(val, &endptr, 10);
if (errno != ERANGE && ready >= INT_MIN && ready <= INT_MAX) {
    server->ready = (int)ready;
}
```

This prevents undefined behavior from out-of-range input. `strtol()` reports range overflow through `errno == ERANGE`, and the explicit `INT_MIN` / `INT_MAX` check ensures the final cast to `int` is safe.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/proxy/balancers/mod_lbmethod_heartbeat.c b/modules/proxy/balancers/mod_lbmethod_heartbeat.c
index 0534e5b..c7eedb8 100644
--- a/modules/proxy/balancers/mod_lbmethod_heartbeat.c
+++ b/modules/proxy/balancers/mod_lbmethod_heartbeat.c
@@ -14,6 +14,9 @@
  * limitations under the License.
  */
 
+#include <errno.h>
+#include <limits.h>
+
 #include "mod_proxy.h"
 #include "scoreboard.h"
 #include "ap_mpm.h"
@@ -183,7 +186,14 @@ static apr_status_t readfile_heartbeats(const char *path, apr_hash_t *servers,
             }
 
             if ((val = apr_table_get(hbt, "ready"))) {
-                server->ready = atoi(val);
+                char *endptr;
+                long ready;
+
+                errno = 0;
+                ready = strtol(val, &endptr, 10);
+                if (errno != ERANGE && ready >= INT_MIN && ready <= INT_MAX) {
+                    server->ready = (int)ready;
+                }
             }
 
             if ((val = apr_table_get(hbt, "lastseen"))) {
```