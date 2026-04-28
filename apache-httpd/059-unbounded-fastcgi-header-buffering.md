# Unbounded FastCGI Header Buffering

## Classification

Resource lifecycle bug, severity medium, confidence certain.

## Affected Locations

`modules/proxy/mod_proxy_fcgi.c:861`

## Summary

`mod_proxy_fcgi` buffered FastCGI STDOUT bytes indefinitely while waiting for a CGI header terminator. A FastCGI backend that continuously sent STDOUT data without `\r\n\r\n` or `\n\n` caused each pre-header chunk to be set aside in a request-lifetime pool with no cumulative size limit, allowing unbounded per-request memory growth.

## Provenance

Verified from supplied source, reproduced by the provided analysis, and patched in `059-unbounded-fastcgi-header-buffering.patch`.

Scanner provenance: https://swival.dev

## Preconditions

A configured FastCGI backend sends endless STDOUT bytes without a header terminator.

## Proof

Backend input enters `dispatch()` through `get_data()` and is inserted into the output brigade as transient buckets. Before headers are complete, `handle_headers()` scans each read buffer.

When `handle_headers()` does not find a terminator, the old code executed:

```c
apr_bucket_setaside(b, setaside_pool);
```

with no cumulative accounting or maximum. The brigade was not cleaned in that branch, and `setaside_pool` was cleared only after headers were found. Since continuous backend data prevents socket timeout behavior from ending the request, repeated FastCGI records caused all pre-header STDOUT bytes to persist until request completion.

`AP_FCGI_MAX_CONTENT_LEN` and `iobuf_size` only bounded individual read or record sizes. They did not bound accumulated pre-header buffering. `ap_scan_script_header_err_brigade_ex()` did not mitigate the issue because it is only called after `handle_headers()` has already found the header terminator.

## Why This Is A Real Bug

The vulnerable branch retains attacker-controlled backend response bytes in a pool whose lifetime spans the request. The only release path is successful header completion, which the backend can intentionally avoid. Therefore a malicious or broken FastCGI backend can keep a proxied request alive while forcing httpd to retain increasing memory, leading to practical worker or process memory exhaustion.

## Fix Requirement

Enforce a maximum cumulative buffered header size for FastCGI responses and abort dispatch when the limit is exceeded.

## Patch Rationale

The patch adds `header_buffered` in `dispatch()` and increments it only in the path where response bytes are being preserved because headers are still incomplete.

Before setting aside another bucket, the patch checks whether adding the current `readbuflen` would exceed `HUGE_STRING_LEN`. If so, it logs an error, sets `rv = APR_ENOSPC`, and breaks out of dispatch. This converts unbounded retention into a bounded failure path while preserving existing behavior for valid FastCGI responses whose headers fit within the existing large-header limit.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/proxy/mod_proxy_fcgi.c b/modules/proxy/mod_proxy_fcgi.c
index 128cf1e..e91b2b6 100644
--- a/modules/proxy/mod_proxy_fcgi.c
+++ b/modules/proxy/mod_proxy_fcgi.c
@@ -611,6 +611,7 @@ static apr_status_t dispatch(proxy_conn_rec *conn, proxy_dir_conf *conf,
     apr_pollfd_t *flushpoll = NULL;
     apr_int32_t flushpoll_fd;
     int header_state = HDR_STATE_READING_HEADERS;
+    apr_size_t header_buffered = 0;
     char stack_iobuf[AP_IOBUFSIZE];
     apr_size_t iobuf_size = AP_IOBUFSIZE;
     char *iobuf = stack_iobuf;
@@ -907,6 +908,14 @@ recv_again:
                             /* We're still looking for the end of the
                              * headers, so this part of the data will need
                              * to persist. */
+                            if (header_buffered > HUGE_STRING_LEN - readbuflen) {
+                                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10501)
+                                              "FastCGI response headers exceeded %d bytes",
+                                              HUGE_STRING_LEN);
+                                rv = APR_ENOSPC;
+                                break;
+                            }
+                            header_buffered += readbuflen;
                             apr_bucket_setaside(b, setaside_pool);
                         }
                     } else {
```