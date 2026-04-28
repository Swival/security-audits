# InputSed filtering bypass by read mode

## Classification

Logic error, medium severity.

## Affected Locations

`modules/filters/mod_sed.c:395`

## Summary

`sed_request_filter` bypassed configured `InputSed` transformations whenever the request body consumer used an input mode other than `AP_MODE_READBYTES`. The filter delegated directly to the next input filter before checking whether `InputSed` rules existed, so supported downstream modes such as `AP_MODE_GETLINE` could return raw request body data.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `InputSed` is configured.
- The `Sed` input filter is inserted into the request input filter chain, for example with `SetInputFilter Sed`.
- A request body consumer reads input using a non-`AP_MODE_READBYTES` mode, such as `AP_MODE_GETLINE`.

## Proof

At `modules/filters/mod_sed.c:395`, the original implementation returned immediately for every mode other than `AP_MODE_READBYTES`:

```c
if (mode != AP_MODE_READBYTES) {
    return ap_get_brigade(f->next, bb, mode, block, readbytes);
}
```

That branch executes before `InputSed` configuration is evaluated and before any sed processing context is initialized.

As a result, execution skips:

- `init_context`
- `sed_eval_buffer`
- `sed_write_output`
- `sed_finalize_eval`

The reproducer confirms that a downstream request body read using `AP_MODE_GETLINE` reaches this branch and receives data from lower filters without sed processing. The lower HTTP request-body filter supports `AP_MODE_GETLINE`, rejecting only modes other than `READBYTES` or `GETLINE` at `modules/http/http_filters.c:355` and continuing body reads with that mode at `modules/http/http_filters.c:586`.

With `SetInputFilter Sed` and an `InputSed` rule such as:

```apache
InputSed s/secret/redacted/g
```

a body read in `AP_MODE_READBYTES` is transformed, while the same body read in `AP_MODE_GETLINE` is returned raw.

## Why This Is A Real Bug

`InputSed` is a configured request-body transformation mechanism. Its behavior should not depend on the read mode selected by the request body consumer in a way that silently bypasses configured transformations.

The original code allowed callers using `AP_MODE_GETLINE` to receive unfiltered request body data even though `InputSed` was configured and the `Sed` input filter was active. This creates a practical bypass for applications or modules relying on `InputSed` for request-body normalization, filtering, or redaction.

## Fix Requirement

When `InputSed` rules are configured, the filter must not silently pass unsupported read modes through unmodified. It must either:

- apply `InputSed` processing for supported modes, or
- reject or normalize unsupported modes before returning data to the caller.

## Patch Rationale

The patch moves the mode check after the `InputSed` configuration check:

```diff
-    if (mode != AP_MODE_READBYTES) {
-        return ap_get_brigade(f->next, bb, mode, block, readbytes);
-    }
-
     if ((sed_cfg == NULL) || (sed_cfg->sed_cmds == NULL)) {
         /* No sed expression */
         return ap_get_brigade(f->next, bb, mode, block, readbytes);
     }
 
+    if (mode != AP_MODE_READBYTES) {
+        return APR_ENOTIMPL;
+    }
+
```

This preserves pass-through behavior when no `InputSed` rules are configured, while preventing configured transformations from being silently bypassed through unsupported read modes.

Returning `APR_ENOTIMPL` for non-`AP_MODE_READBYTES` modes makes the unsupported state explicit instead of returning unfiltered request data.

## Residual Risk

None

## Patch

`117-input-filtering-bypass-by-read-mode.patch`

```diff
diff --git a/modules/filters/mod_sed.c b/modules/filters/mod_sed.c
index 12cb04a..d7a5fab 100644
--- a/modules/filters/mod_sed.c
+++ b/modules/filters/mod_sed.c
@@ -392,15 +392,15 @@ static apr_status_t sed_request_filter(ap_filter_t *f,
     apr_bucket_brigade *bbinp;
     sed_expr_config *sed_cfg = &cfg->input;
 
-    if (mode != AP_MODE_READBYTES) {
-        return ap_get_brigade(f->next, bb, mode, block, readbytes);
-    }
-
     if ((sed_cfg == NULL) || (sed_cfg->sed_cmds == NULL)) {
         /* No sed expression */
         return ap_get_brigade(f->next, bb, mode, block, readbytes);
     }
 
+    if (mode != AP_MODE_READBYTES) {
+        return APR_ENOTIMPL;
+    }
+
     if (!ctx) {
         if (!ap_is_initial_req(f->r)) {
             ap_remove_input_filter(f);
```