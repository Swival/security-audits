# One-Value Median Reads Past Array

## Classification

Out-of-bounds read, medium severity.

## Affected Locations

`modules/mod_delay.c:166`

## Summary

`delay_get_median()` used a one-based median index when calling `delay_select_k()`, but the backing `array_header` stores elements at zero-based offsets. When the selected protocol row has no prior delay values, the list contains only the current interval. The code then requests index `1` from a one-element array, causing `delay_select_k()` to read past the allocated pool array.

## Provenance

Verified and reproduced from Swival Security Scanner findings: https://swival.dev

Confidence: certain.

## Preconditions

- `mod_delay` is enabled.
- `DelayTable` is enabled.
- The selected protocol row has no prior values.
- An unauthenticated FTP client sends a first `USER` or `PASS` command that reaches `delay_post_user()` or `delay_post_pass()`.

## Proof

For an empty selected protocol row:

1. `delay_post_user()` or `delay_post_pass()` computes an interval for an unauthenticated session.
2. The handler calls `delay_get_median(cmd->tmp_pool, rownum, proto, interval)`.
3. `delay_get_median()` creates `list = make_array(p, 1, sizeof(long))`.
4. No prior table values are pushed because the protocol row is empty.
5. The current `interval` is pushed, so `list->nelts == 1` and the only valid element is `elts[0]`.
6. The vulnerable code calls `delay_select_k(((list->nelts + 1) / 2), list)`, which passes `k == 1`.
7. `delay_select_k()` initializes `l = 1` and `ir = values->nelts - 1`, so `ir == 0`.
8. The `ir <= l+1` branch is immediately taken and returns `elts[k]`.
9. With `k == 1`, this reads `elts[1]` past the one-element array.

The existing guards only require `delay_engine`, `delay_tab.dt_enabled`, and not already authenticated, all compatible with an unauthenticated first `USER` or `PASS`.

## Why This Is A Real Bug

The array contains one `long` allocated by `make_array(p, 1, sizeof(long))`, and `push_array()` writes the current interval at index `0`. Passing `k == 1` to `delay_select_k()` causes a direct read from `elts[1]`, outside the valid array bounds. The trigger is reachable before authentication through normal FTP command handling when `DelayTable` is enabled and the relevant row is cold.

## Fix Requirement

Use a zero-based median index, or explicitly handle `list->nelts == 1` before calling `delay_select_k()`.

## Patch Rationale

The patch changes the selected median index from:

```c
((list->nelts + 1) / 2)
```

to:

```c
(list->nelts / 2)
```

This makes the requested median offset zero-based. For the reproduced one-value case, `list->nelts / 2` evaluates to `0`, so `delay_select_k()` returns `elts[0]`, the only valid element. For odd counts, it still selects the middle element by zero-based index.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/mod_delay.c b/modules/mod_delay.c
index 2fc2808ac..09b14cbc9 100644
--- a/modules/mod_delay.c
+++ b/modules/mod_delay.c
@@ -301,7 +301,7 @@ static long delay_get_median(pool *p, unsigned int rownum, const char *protocol,
   pr_trace_msg(trace_channel, 6, "selecting median interval from %d %s",
     list->nelts, list->nelts != 1 ? "values" : "value");
 
-  median = delay_select_k(((list->nelts + 1) / 2), list);
+  median = delay_select_k((list->nelts / 2), list);
   if (median >= 0) {
 
     /* Enforce an additional restriction: no delays over a hard limit. */
```