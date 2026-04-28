# PATH_INFO Controls Extension Handler

## Classification

Trust-boundary violation, medium severity.

## Affected Locations

- `modules/http/mod_mime.c:900`

## Summary

When `ModMimeUsePathInfo` is enabled, `mod_mime` appends `r->path_info` to `r->filename` and parses the combined string for extensions. Extensions that exist only in `PATH_INFO` can therefore match `AddHandler` mappings and assign `r->handler`, causing the request to be dispatched to a handler not selected by the actual target filename.

## Provenance

- Verified by Swival Security Scanner: https://swival.dev
- Reproduced manually from the request-processing path and handler dispatch path.

## Preconditions

- `ModMimeUsePathInfo` is enabled.
- `PATH_INFO` contains an extension mapped by `AddHandler`.
- Directory walking resolves `r->filename` to an existing non-matching file while leaving the mapped extension in `r->path_info`, for example `/existing-file/marker.cgi`.

## Proof

`find_ct()` uses `r->filename` as the MIME lookup input unless `conf->use_path_info & 1` is set. In that case it constructs:

```c
resource_name = apr_pstrcat(r->pool, r->filename, r->path_info, NULL);
```

The extension parser then walks suffixes in `resource_name`. If an extension from the appended `PATH_INFO` matches an `AddHandler` entry, the old code executes:

```c
if (exinfo->handler && r->proxyreq == PROXYREQ_NONE) {
    r->handler = exinfo->handler;
}
```

This path is reachable during normal request handling because `mod_mime` registers `find_ct()` as a type checker at `modules/http/mod_mime.c:1020`, and type checkers are run by `ap_run_type_checker()` at `server/request.c:412`.

The selected handler is later invoked by `ap_invoke_handler()` through `ap_run_handler(r)` at `server/config.c:443`. For CGI, `mod_cgi` dispatches when `r->handler` is `cgi-script` at `modules/generators/mod_cgi.c:529`; it rejects `PATH_INFO` only when `AcceptPathInfo Off` has forced `AP_REQ_REJECT_PATH_INFO` at `modules/generators/mod_cgi.c:555`.

## Why This Is A Real Bug

`PATH_INFO` is not the target resource filename. Treating suffixes from `PATH_INFO` as authoritative handler-selection extensions crosses the trust boundary between the resolved file and extra path data. Under the stated configuration, a request for an existing non-`.cgi` resource can be made to select the CGI handler by appending `.cgi` in `PATH_INFO`, bypassing the intended filename-extension boundary established by `AddHandler`.

## Fix Requirement

Handler mappings must never be applied to extensions parsed from `PATH_INFO`. Other MIME metadata behavior can continue to honor `ModMimeUsePathInfo`, but `AddHandler` must be limited to extensions that belong to the resolved filename portion.

## Patch Rationale

The patch records the boundary between `r->filename` and appended `r->path_info` when `ModMimeUsePathInfo` is active:

```c
path_info_start = resource_name + strlen(r->filename);
```

During extension parsing, it records the start of each parsed extension and computes whether the extension crosses into or lies within the `PATH_INFO` portion:

```c
skip_handler = (path_info_start
                && ext_start + strlen(ext) > path_info_start);
```

It then prevents handler assignment for those extensions:

```c
if (exinfo->handler && !skip_handler && r->proxyreq == PROXYREQ_NONE) {
```

This preserves existing extension parsing and metadata handling while enforcing that `PATH_INFO` cannot control `r->handler`.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/http/mod_mime.c b/modules/http/mod_mime.c
index 51095a0..b71f535 100644
--- a/modules/http/mod_mime.c
+++ b/modules/http/mod_mime.c
@@ -756,6 +756,7 @@ static int find_ct(request_rec *r)
     apr_array_header_t *exception_list;
     char *ext;
     const char *fn, *fntmp, *type, *charset = NULL, *resource_name, *qm;
+    const char *path_info_start = NULL;
     int found_metadata = 0;
 
     if (r->finfo.filetype == APR_DIR) {
@@ -774,6 +775,7 @@ static int find_ct(request_rec *r)
     /* If use_path_info is explicitly set to on (value & 1 == 1), append. */
     if (conf->use_path_info & 1) {
         resource_name = apr_pstrcat(r->pool, r->filename, r->path_info, NULL);
+        path_info_start = resource_name + strlen(r->filename);
     }
     /*
      * In the reverse proxy case r->filename might contain a query string if
@@ -826,16 +828,22 @@ static int find_ct(request_rec *r)
 
     /* Parse filename extensions which can be in any order
      */
-    while (*fn && (ext = ap_getword(r->pool, &fn, '.'))) {
+    while (*fn) {
+        const char *ext_start = fn;
         const extension_info *exinfo = NULL;
         int found;
+        int skip_handler;
         char *extcase;
 
+        ext = ap_getword(r->pool, &fn, '.');
+
         if (*ext == '\0') {  /* ignore empty extensions "bad..html" */
             continue;
         }
 
         found = 0;
+        skip_handler = (path_info_start
+                        && ext_start + strlen(ext) > path_info_start);
 
         /* Save the ext in extcase before converting it to lower case.
          */
@@ -898,7 +906,7 @@ static int find_ct(request_rec *r)
              * make any contribution to metadata negotiation, so they must have
              * been explicitly requested by name.
              */
-            if (exinfo->handler && r->proxyreq == PROXYREQ_NONE) {
+            if (exinfo->handler && !skip_handler && r->proxyreq == PROXYREQ_NONE) {
                 r->handler = exinfo->handler;
                 if (conf->multimatch & MULTIMATCH_HANDLERS) {
                     found = 1;
```