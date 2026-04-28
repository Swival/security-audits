# Resultset Use After Pool Destroy

## Classification

Memory safety, medium severity, use-after-free / use-after-destroyed APR pool.

## Affected Locations

`modules/lua/lua_dbd.c:248`

`modules/lua/lua_dbd.c:255`

`modules/lua/lua_dbd.c:275`

`modules/lua/lua_dbd.c:344`

`modules/lua/lua_dbd.c:435`

## Summary

Lua APR_DBD resultsets stored the database handle pool in `resultset->pool`. For direct APR_DBD handles, `db:close()` destroys that pool. If Lua keeps a resultset and invokes it after closing the database handle, `lua_db_get_row()` passes the stale pool and stale DBD results to `apr_dbd_get_row()`, risking invalid memory access.

The patch gives each resultset its own APR pool and destroys that pool from a resultset `__gc` handler, decoupling resultset lifetime from database handle closure.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Lua keeps a resultset after closing its APR_DBD database handle.

A successful `db:select()` or prepared `statement:select()` returns a resultset with at least one column.

The resultset is invoked after `db:close()` destroys the direct APR_DBD handle pool.

## Proof

`db:select()` creates a resultset userdata and stores `resultset->pool = db->pool`.

`statement:select()` similarly stores `resultset->pool = st->db->pool`.

For direct APR_DBD handles, `db:close()` calls `apr_dbd_close(db->driver, db->handle)` and then `apr_pool_destroy(db->pool)`.

The resultset object remains reachable from Lua and is not invalidated by `db:close()`.

A later resultset invocation reaches `lua_db_get_row()`, which calls:

```c
apr_dbd_get_row(res->driver, res->pool, res->results, &row, row_no)
```

At that point, `res->pool` refers to a destroyed pool, and `res->results` was allocated from the same destroyed lifetime. The first dangerous operation is the `apr_dbd_get_row()` call using `res->pool` and `res->results`; subsequent `apr_dbd_get_entry()` and `apr_dbd_get_name()` calls also operate on data derived from that stale resultset.

## Why This Is A Real Bug

APR pools own the lifetime of allocations made from them. Destroying `db->pool` invalidates allocations and objects tied to that pool, including the DBD result storage selected into that pool.

Lua’s resultset userdata has an independent lifetime and can outlive the database handle table. The code did not enforce invalidation or ownership coupling between the database handle and resultsets. Therefore a valid Lua operation sequence can cause C code to pass destroyed APR pool state into APR DBD APIs.

The reproduced trigger is: acquire a direct APR_DBD handle, run a successful `select`, keep the returned resultset table, call `db:close()`, then call the resultset.

## Fix Requirement

Resultsets must not depend on a database handle pool that can be destroyed while the resultset remains reachable.

A valid fix must either:

- keep resultset storage alive independently for the lifetime of the resultset, or
- invalidate all dependent resultsets before destroying the database handle pool and prevent later use.

## Patch Rationale

The patch implements independent resultset lifetime management.

It adds `lua_db_result_gc()`, which destroys `res->pool` when the resultset userdata is garbage collected.

It changes `lua_db_select()` to allocate a dedicated `res_pool` before `apr_dbd_select()` and pass that pool to APR DBD. The resulting `lua_db_result_set` stores `resultset->pool = res_pool`, so later row iteration no longer uses `db->pool`.

It applies the same independent resultset pool pattern to `lua_db_prepared_select()` by using `res_pool` for `apr_dbd_pselect()` and storing that pool in the resultset.

It destroys `res_pool` on select failure or when no resultset is returned, avoiding leaks on non-resultset paths.

This satisfies the fix requirement because closing the database handle may still destroy `db->pool`, but existing resultsets now retain their own APR pool until Lua garbage collection.

## Residual Risk

None

## Patch

`089-resultset-use-after-pool-destroy.patch`

```diff
diff --git a/modules/lua/lua_dbd.c b/modules/lua/lua_dbd.c
index 1b8d5b7..b65d4a3 100644
--- a/modules/lua/lua_dbd.c
+++ b/modules/lua/lua_dbd.c
@@ -50,6 +50,17 @@ static lua_db_result_set *lua_get_result_set(lua_State *L)
     return (lua_db_result_set *) lua_topointer(L, -1);
 }
 
+static int lua_db_result_gc(lua_State *L)
+{
+    lua_db_result_set *res = lua_touserdata(L, 1);
+
+    if (res && res->pool) {
+        apr_pool_destroy(res->pool);
+        res->pool = NULL;
+    }
+    return 0;
+}
+
 
 /*
    =============================================================================
@@ -323,10 +334,17 @@ int lua_db_select(lua_State *L)
             /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
             int cols;
             apr_dbd_results_t   *results = 0;
+            apr_pool_t          *res_pool = NULL;
             lua_db_result_set* resultset = NULL;
             /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
 
-            rc = apr_dbd_select(db->driver, db->pool, db->handle,
+            rc = apr_pool_create(&res_pool, NULL);
+            if (rc != APR_SUCCESS) {
+                lua_pushnil(L);
+                lua_pushliteral(L, "Could not allocate memory for result set!");
+                return 2;
+            }
+            rc = apr_dbd_select(db->driver, res_pool, db->handle,
                                 &results, statement, 0);
             if (rc == APR_SUCCESS) {
                 
@@ -337,10 +355,15 @@ int lua_db_select(lua_State *L)
                     resultset = lua_newuserdata(L, sizeof(lua_db_result_set));
                     resultset->cols = cols;
                     resultset->driver = db->driver;
-                    resultset->pool = db->pool;
+                    resultset->pool = res_pool;
                     resultset->rows = apr_dbd_num_tuples(db->driver, results);
                     resultset->results = results;
                     luaL_newmetatable(L, "lua_apr.dbselect");
+                    lua_pushliteral(L, "__gc");
+                    lua_pushcfunction(L, lua_db_result_gc);
+                    lua_rawset(L, -3);
+                    lua_setmetatable(L, -2);
+                    luaL_newmetatable(L, "lua_apr.dbselect");
                     lua_pushliteral(L, "__call");
                     lua_pushcfunction(L, lua_db_get_row);
                     lua_rawset(L, -3);
@@ -348,9 +371,11 @@ int lua_db_select(lua_State *L)
                     lua_rawseti(L, -2, 0);
                     return 1;
                 }
+                apr_pool_destroy(res_pool);
                 return 0;
             }
             else {
+                apr_pool_destroy(res_pool);
 
                 /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
                 const char  *err = apr_dbd_error(db->driver, db->handle, rc);
@@ -415,9 +440,16 @@ int lua_db_prepared_select(lua_State *L)
         /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
         int cols;
         apr_dbd_results_t   *results = 0;
+        apr_pool_t          *res_pool = NULL;
         /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
 
-        rc = apr_dbd_pselect(st->db->driver, st->db->pool, st->db->handle,
+        rc = apr_pool_create(&res_pool, NULL);
+        if (rc != APR_SUCCESS) {
+            lua_pushnil(L);
+            lua_pushliteral(L, "Could not allocate memory for result set!");
+            return 2;
+        }
+        rc = apr_dbd_pselect(st->db->driver, res_pool, st->db->handle,
                                 &results, st->statement, 0, have, vars);
         if (rc == APR_SUCCESS) {
 
@@ -430,10 +462,15 @@ int lua_db_prepared_select(lua_State *L)
             resultset = lua_newuserdata(L, sizeof(lua_db_result_set));
             resultset->cols = cols;
             resultset->driver = st->db->driver;
-            resultset->pool = st->db->pool;
+            resultset->pool = res_pool;
             resultset->rows = apr_dbd_num_tuples(st->db->driver, results);
             resultset->results = results;
             luaL_newmetatable(L, "lua_apr.dbselect");
+            lua_pushliteral(L, "__gc");
+            lua_pushcfunction(L, lua_db_result_gc);
+            lua_rawset(L, -3);
+            lua_setmetatable(L, -2);
+            luaL_newmetatable(L, "lua_apr.dbselect");
             lua_pushliteral(L, "__call");
             lua_pushcfunction(L, lua_db_get_row);
             lua_rawset(L, -3);
@@ -443,6 +480,7 @@ int lua_db_prepared_select(lua_State *L)
             
         }
         else {
+            apr_pool_destroy(res_pool);
 
             /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
             const char  *err = apr_dbd_error(st->db->driver, st->db->handle, rc);
```