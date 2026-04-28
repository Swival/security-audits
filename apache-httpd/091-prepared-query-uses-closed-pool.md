# Prepared Query Uses Closed Pool

## Classification

Resource lifecycle bug. Severity: medium. Confidence: certain.

## Affected Locations

`modules/lua/lua_dbd.c:505`

## Summary

`lua_db_prepared_query()` allocates argument storage from `st->db->pool` before verifying that the prepared statement's originating database handle is still alive. If Lua closes the database after preparing a statement, `db:close()` destroys the APR pool and sets `db->pool = NULL`; a later `statement:query(...)` can pass that NULL pool to `apr_pcalloc()`, risking a crash or invalid memory operation instead of returning the existing closed-connection Lua error.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Lua code prepares a statement from an APR_DBD-backed database handle.
- Lua code closes that database handle.
- Lua code keeps the prepared statement table reachable.
- Lua code calls `statement:query(...)` with enough arguments to pass the prepared-statement argument count check.

## Proof

`lua_db_prepare()` stores the originating database handle in the prepared statement userdata:

```c
st->db = db;
```

`lua_db_close()` destroys the APR_DBD pool and marks the handle closed:

```c
if (db->pool) apr_pool_destroy(db->pool);
db->alive = 0;
db->pool = NULL;
```

Before the patch, `lua_db_prepared_query()` computed `have`, checked only the argument count, and then allocated using `st->db->pool`:

```c
vars = apr_pcalloc(st->db->pool, have*sizeof(char *));
```

The liveness check existed only after that allocation:

```c
if (st->db && st->db->alive) {
```

A minimal reachable trigger is:

```lua
local st = db:prepare(r, "update t set v = %s")
db:close()
st:query("x")
```

After `db:close()`, `st->db->pool` is NULL. The subsequent `st:query("x")` reaches `apr_pcalloc(st->db->pool, ...)` before the closed-connection error path.

## Why This Is A Real Bug

The prepared statement object intentionally outlives the database close in Lua because it is a separate table holding userdata. `db:close()` does not invalidate or clear existing prepared statement userdata; it only marks the shared `lua_db_handle` dead and NULLs its pool. Therefore the ordering in `lua_db_prepared_query()` allows normal Lua code to use a closed handle's pool before the function checks `st->db->alive`. The practical impact is a crash or invalid APR allocation path where the API should return:

```text
Database connection seems to be closed, please reacquire it.
```

## Fix Requirement

Check `st->db` and `st->db->alive` before any dereference or use of `st->db->pool` in `lua_db_prepared_query()`.

## Patch Rationale

The patch moves the existing closed-connection behavior ahead of the APR allocation. This preserves the function's established error contract while preventing `apr_pcalloc()` from receiving a NULL or destroyed pool through a closed database handle.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/lua/lua_dbd.c b/modules/lua/lua_dbd.c
index 1b8d5b7..eccc77d 100644
--- a/modules/lua/lua_dbd.c
+++ b/modules/lua/lua_dbd.c
@@ -495,6 +495,12 @@ int lua_db_prepared_query(lua_State *L)
                 st->variables, have);
         return 2;
     }
+    if (!st->db || !st->db->alive) {
+        lua_pushboolean(L, 0);
+        lua_pushliteral(L, 
+                "Database connection seems to be closed, please reacquire it.");
+        return (2);
+    }
     vars = apr_pcalloc(st->db->pool, have*sizeof(char *));
     for (x = 0; x < have; x++) {
         vars[x] = lua_tostring(L, x + 2);
```