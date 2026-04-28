# Prepared Select Uses Closed Pool

## Classification

Resource lifecycle bug, medium severity. Confidence: certain.

## Affected Locations

`modules/lua/lua_dbd.c:407`

Scanner-reported location: `modules/lua/lua_dbd.c:416`

## Summary

`lua_db_prepared_select()` allocates argument storage from `st->db->pool` before verifying that the prepared statement still references a live database handle. After `db:close()`, the shared handle has `alive = 0` and `pool = NULL`, so a retained prepared statement can pass a NULL APR pool to `apr_pcalloc()` instead of returning the intended closed-connection error.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was manually reproduced and patched from the supplied source and patch evidence.

## Preconditions

Lua code must:

- acquire a database handle;
- prepare a statement from that handle;
- retain the prepared statement object;
- close the database handle;
- call `statement:select(...)` with enough arguments for the prepared statement.

## Proof

`lua_db_close()` marks the shared database handle closed and clears its pool:

```c
db->alive = 0;
db->pool = NULL;
```

A retained prepared statement remains callable because `lua_db_prepared_select()` retrieves `st` from the statement table:

```c
lua_rawgeti(L, 1, 0);
st = (lua_db_prepared_statement*) lua_topointer(L, -1);
```

After the argument-count check, the vulnerable code allocates through the stale handle before validating it:

```c
vars = apr_pcalloc(st->db->pool, have*sizeof(char *));
```

Only later does it check:

```c
if (st->db && st->db->alive) {
```

Therefore this sequence is reachable:

```lua
st = db:prepare(r, "select ...")
db:close()
st:select(...)
```

With sufficient arguments, `st:select(...)` reaches `apr_pcalloc(st->db->pool, ...)` while `st->db->pool == NULL`.

## Why This Is A Real Bug

The code already intends to handle closed connections by returning:

```text
Database connection seems to be closed, please reacquire it.
```

However, that guard executes too late. `db:close()` explicitly invalidates the pool used by prepared statements, and `lua_db_prepared_select()` dereferences that pool before checking `st->db`, `st->db->alive`, or `st->db->pool`. This is a real lifecycle ordering bug because normal Lua object retention allows a prepared statement to outlive the live state of its database handle.

## Fix Requirement

Before any use of `st->db->pool`, `lua_db_prepared_select()` must verify that:

- `st->db` is non-NULL;
- `st->db->alive` is true;
- `st->db->pool` is non-NULL.

If any check fails, the function must return the existing closed-connection error immediately.

## Patch Rationale

The patch moves the effective liveness validation before `apr_pcalloc()`. This prevents APR allocation from receiving a NULL pool and preserves the existing API behavior by returning the same closed-connection error already used at the end of the function.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/lua/lua_dbd.c b/modules/lua/lua_dbd.c
index 1b8d5b7..79461e5 100644
--- a/modules/lua/lua_dbd.c
+++ b/modules/lua/lua_dbd.c
@@ -404,6 +404,12 @@ int lua_db_prepared_select(lua_State *L)
                 st->variables, have);
         return 2;
     }
+    if (!st->db || !st->db->alive || !st->db->pool) {
+        lua_pushboolean(L, 0);
+        lua_pushliteral(L, 
+                "Database connection seems to be closed, please reacquire it.");
+        return (2);
+    }
     vars = apr_pcalloc(st->db->pool, have*sizeof(char *));
     for (x = 0; x < have; x++) {
         vars[x] = lua_tostring(L, x + 2);
```