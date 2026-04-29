# getgrset group parsing overflows fixed gid array

## Classification

Out-of-bounds write. Severity: high. Confidence: certain.

## Affected Locations

`modules/mod_auth_unix.c:1185`

## Summary

`get_groups_by_getgrset()` allocates `gid_t group_ids[NGROUPS_MAX]` but bounds the write index with `sizeof(group_ids)`. Since `sizeof(group_ids)` is a byte count, not an element count, oversized `getgrset()` output can allow writes past the `NGROUPS_MAX`-element stack array during FTP login group resolution.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Build has `HAVE_GETGRSET` enabled.
- Earlier group lookup methods return `ENOSYS`, causing fallback to `get_groups_by_getgrset()`.
- Target account selected by the login username has a `getgrset(user)` comma-delimited group list containing more than `NGROUPS_MAX` non-primary group IDs.

## Proof

The reproduced path is:

- An unauthenticated FTP client supplies `USER <name>`.
- The login/auth path dispatches the `getgroups` auth hook and reaches `pw_getgroups()` in `modules/mod_auth_unix.c:1465`.
- `pw_getgroups()` tries `get_groups_by_initgroups()`, then `get_groups_by_getgrouplist()`, then reaches `get_groups_by_getgrset()` when earlier methods return `ENOSYS`.
- `get_groups_by_getgrset()` allocates `gid_t group_ids[NGROUPS_MAX]`.
- The parser increments `ngroups` for comma-delimited group IDs returned by `getgrset(user)`.
- The capacity check compares `ngroups >= sizeof(group_ids)`, allowing up to the byte size of the array rather than the number of `gid_t` elements.
- `group_ids[ngroups] = gid` then writes past the stack array once more than `NGROUPS_MAX` entries are accepted.

## Why This Is A Real Bug

The array has `NGROUPS_MAX` elements, but the guard uses `sizeof(group_ids)`, which evaluates to `NGROUPS_MAX * sizeof(gid_t)` bytes. On platforms where `sizeof(gid_t) > 1`, this permits indexes beyond the valid range. The trigger is reachable before authentication completes by selecting a username whose system group database entry expands to an oversized `getgrset()` list, causing attacker-triggered stack memory corruption in the auth worker.

## Fix Requirement

The parser must compare `ngroups` against the element capacity of `group_ids`, not its byte size. A correct bound is `NGROUPS_MAX` or an equivalent array-element count expression.

## Patch Rationale

The patch changes the guard from:

```c
if (ngroups >= sizeof(group_ids)) {
```

to:

```c
if (ngroups >= NGROUPS_MAX) {
```

This makes the maximum accepted index match the declared array length, so `group_ids[ngroups] = gid` cannot write past `group_ids[NGROUPS_MAX - 1]`.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/mod_auth_unix.c b/modules/mod_auth_unix.c
index 531f4c9f9..5c63b31ef 100644
--- a/modules/mod_auth_unix.c
+++ b/modules/mod_auth_unix.c
@@ -1193,7 +1193,7 @@ static int get_groups_by_getgrset(const char *user, gid_t primary_gid,
 
     pr_signals_handle();
 
-    if (ngroups >= sizeof(group_ids)) {
+    if (ngroups >= NGROUPS_MAX) {
       /* Reached capacity of the group_ids array. */
       break;
     }
```