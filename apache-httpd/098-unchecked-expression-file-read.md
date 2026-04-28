# unchecked expression file read

## Classification

validation gap; severity medium; confidence certain

## Affected Locations

- `server/util_expr_eval.c:978`
- `server/util_expr_eval.c:1106`
- `server/util_expr_eval.c:1117`
- `server/util_expr_eval.c:1155`

## Summary

`file()` expression evaluation opened the evaluated path directly with `apr_file_open()` without first applying `ap_stat_check()` through `stat_check()`. Other file-related expression operations already perform this validation before filesystem access. When a configuration expression uses `file()` with request-controlled path input, a request can cause the server process to read any openable configured path, up to the existing 10 MiB cap.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- A configuration expression uses `file()`.
- The `file()` argument contains request-controlled path input.
- The expression is parsed in a context where `AP_EXPR_FLAG_RESTRICTED` is not set.

## Proof

`file()` is registered as a string function provider:

- `string_func_providers` contains `{ file_func, "file", NULL, 1 }`.

During evaluation, the argument is evaluated and passed to the string function:

- `ap_expr_eval_string_func()` calls the provider with `ap_expr_eval_word(ctx, arg)`.

Before the patch, `file_func()` passed `arg` directly to:

```c
apr_file_open(&fp, arg, APR_READ|APR_BUFFERED, APR_OS_DEFAULT, ctx->p)
```

without calling `stat_check()`. In contrast, related file operations validate first:

- `filesize_func()` calls `stat_check()` before `apr_stat()`.
- file test operators such as `-d`, `-e`, `-f`, `-s`, `-L`, `-h`, `-x`, and `-F` call `stat_check()` before filesystem checks.

`AP_EXPR_FLAG_RESTRICTED` blocks `file()` only when restricted parsing is explicitly requested. It does not validate paths when `file()` is available.

## Why This Is A Real Bug

The code had an inconsistent validation boundary: equivalent file expression functionality used `stat_check()`, but `file()` skipped it before opening and reading the path. That allows request-influenced expression input to bypass central path validation and read arbitrary files accessible to the server process. On Windows, this also bypasses `UNCList` enforcement because `ap_stat_check()` maps to UNC validation, while the unchecked `apr_file_open()` path avoided that check.

## Fix Requirement

Call `stat_check(ctx, data, arg)` in `file_func()` before `apr_file_open()`, and fail closed by returning an empty string when validation does not return `APR_SUCCESS`.

## Patch Rationale

The patch adds a forward declaration for `stat_check()` before `file_func()` and invokes it at the start of `file_func()`:

```c
if (APR_SUCCESS != stat_check(ctx, data, arg)) {
    return "";
}
```

This aligns `file()` with `filesize()` and the file test operators, preserving existing error reporting from `stat_check()` and preventing the open/read path from executing on disallowed paths.

## Residual Risk

None

## Patch

```diff
diff --git a/server/util_expr_eval.c b/server/util_expr_eval.c
index 038d5a0..be7e069 100644
--- a/server/util_expr_eval.c
+++ b/server/util_expr_eval.c
@@ -1103,6 +1103,8 @@ static const char *ldap_func(ap_expr_eval_ctx_t *ctx, const void *data,
 #endif
 
 #define MAX_FILE_SIZE 10*1024*1024
+static apr_status_t stat_check(ap_expr_eval_ctx_t *ctx, const void *data,
+                               const char *arg);
 static const char *file_func(ap_expr_eval_ctx_t *ctx, const void *data,
                              char *arg)
 {
@@ -1112,6 +1114,9 @@ static const char *file_func(ap_expr_eval_ctx_t *ctx, const void *data,
     apr_size_t len;
     apr_finfo_t finfo;
 
+    if (APR_SUCCESS != stat_check(ctx, data, arg)) {
+        return "";
+    }
     if (apr_file_open(&fp, arg, APR_READ|APR_BUFFERED,
                       APR_OS_DEFAULT, ctx->p) != APR_SUCCESS) {
         *ctx->err = apr_psprintf(ctx->p, "Cannot open file %s", arg);
@@ -1147,7 +1152,8 @@ static const char *file_func(ap_expr_eval_ctx_t *ctx, const void *data,
     return buf;
 }
 
-static apr_status_t stat_check(ap_expr_eval_ctx_t *ctx, const void *data, const char *arg)
+static apr_status_t stat_check(ap_expr_eval_ctx_t *ctx, const void *data,
+                               const char *arg)
 {
     apr_status_t rv = APR_SUCCESS;
     if (APR_SUCCESS != (rv = ap_stat_check(arg, ctx->p))) {
```