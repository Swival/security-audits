# Uninitialized PID Cleanup

## Classification

Resource lifecycle bug, medium severity. Confidence: certain.

## Affected Locations

`modules/generators/mod_cgid.c:1707`

## Summary

`include_cmd()` allocates `struct cleanup_script_info` for SSI `exec cmd` handling and only initializes `info->pid` when `get_cgi_pid()` succeeds. On PID lookup failure, the function logs a debug message but still registered `cleanup_script` unconditionally. Request-pool cleanup then used the uninitialized `pid_t` and could signal an unrelated process.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

- An SSI `exec cmd` request reaches `include_cmd()`.
- `get_cgi_pid()` fails after `info` is allocated.
- Request-pool cleanup later runs the registered cleanup handler.

## Proof

In `include_cmd()`, `info` is allocated with `apr_palloc()`, so its fields are not zero-initialized. The code sets:

```c
info->conf = conf;
info->r = r;
rv = get_cgi_pid(r, conf, &(info->pid));
```

If `get_cgi_pid()` returns success, `info->pid` is initialized and `cleanup_script` is registered inside the success branch.

If `get_cgi_pid()` fails, only this debug log runs:

```c
ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, "error determining cgi PID (for SSI)");
```

Execution then continued to an unconditional cleanup registration using the same `info`:

```c
apr_pool_cleanup_register(r->pool, info,
                          cleanup_script,
                          apr_pool_cleanup_null);
```

During cleanup, `cleanup_script()` passed `info->pid` to `cleanup_nonchild_process()`. That function immediately called `kill(pid, SIGTERM)`, and could later call `kill(pid, SIGKILL)` twice.

Because `info->pid` was indeterminate on the failure path, cleanup could signal an arbitrary PID value from pool memory, including special values such as `0`.

## Why This Is A Real Bug

The failure path is reachable when an SSI command request reaches `include_cmd()` and the daemon PID lookup fails. The registered cleanup is not inert: it calls process-signaling code through `cleanup_nonchild_process()`. The signal is issued by the httpd child process and can terminate or attempt to terminate processes accessible to that user.

This is not merely a duplicate-cleanup issue. The success path already registers cleanup in the guarded branch, but the failure path independently registers cleanup with an uninitialized PID.

## Fix Requirement

Register `cleanup_script` only after `get_cgi_pid()` succeeds, or otherwise initialize and guard `info->pid` before cleanup can use it.

## Patch Rationale

The patch removes the unconditional `apr_pool_cleanup_register()` after the success/failure branch. The existing guarded registration inside `if (APR_SUCCESS == rv)` remains, so cleanup is installed only when `info->pid` has been populated by `get_cgi_pid()`.

This also eliminates duplicate cleanup registration on the success path.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/generators/mod_cgid.c b/modules/generators/mod_cgid.c
index a0ef2b5..e8e8a82 100644
--- a/modules/generators/mod_cgid.c
+++ b/modules/generators/mod_cgid.c
@@ -1764,10 +1764,6 @@ static int include_cmd(include_ctx_t *ctx, ap_filter_t *f,
         ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r, "error determining cgi PID (for SSI)");
     }
 
-    apr_pool_cleanup_register(r->pool, info,
-                              cleanup_script,
-                              apr_pool_cleanup_null);
-
     /* We are putting the socket discriptor into an apr_file_t so that we can
      * use a pipe bucket to send the data to the client.  APR will create
      * a cleanup for the apr_file_t which will close the socket, so we'll
```