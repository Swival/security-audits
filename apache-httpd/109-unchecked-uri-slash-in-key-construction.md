# Unchecked URI Slash in Authn Socache Key Construction

## Classification

Memory safety; high severity; denial of service via undefined pointer arithmetic.

## Affected Locations

`modules/aaa/mod_authn_socache.c:276`

## Summary

`construct_key()` assumes `r->uri` contains `/` when `AuthnCacheContext` is the default `directory` context. If `r->uri` is slashless, including an empty URI on reachable internal subrequest paths, `strrchr(r->uri, '/')` returns `NULL`. The code then subtracts `NULL` from `r->uri` and uses the resulting invalid length for allocation and `strncat()`, producing undefined behavior and practical worker-process crashes.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `mod_authn_socache` is configured and used as an authentication provider.
- `AuthnCacheContext` remains the default `directory` context.
- Authentication cache lookup or store reaches `construct_key()`.
- The request record has a slashless `r->uri`, demonstrated with `r->uri == ""` through an internal file subrequest path.

## Proof

`check_password()` and `ap_authn_cache_store()` both call `construct_key()` with the configured cache context.

In the default `directory` context, the vulnerable sequence is:

```c
char *slash = strrchr(r->uri, '/');
new_context = apr_palloc(r->pool, slash - r->uri +
                         strlen(r->server->server_hostname) + 1);
strncat(new_context, r->uri, slash - r->uri);
```

When `r->uri == ""`, `strrchr("", '/')` returns `NULL`. `slash - r->uri` is invalid pointer subtraction because `slash` does not point into the same object as `r->uri`. Sanitizer confirmation showed a slashless URI causing AddressSanitizer to abort on an impossibly large allocation request.

## Why This Is A Real Bug

The code violates C pointer arithmetic invariants before any bounds check occurs. The invalid result is then trusted as a size for `apr_palloc()` and as a byte count for `strncat()`. This is not only theoretical undefined behavior: reproduction confirmed a crash/DoS condition under a plausible authn-socache configuration via internal subrequest authentication with an empty `r->uri`.

## Fix Requirement

Handle the `NULL` result from `strrchr(r->uri, '/')` before subtracting from `r->uri`. A slashless URI must produce a valid zero-length URI prefix or be rejected before key construction continues.

## Patch Rationale

The patch treats a missing slash as an empty directory prefix by setting `slash = r->uri`. This preserves existing behavior for normal slash-containing URIs while making `slash - r->uri` equal to zero for slashless URIs. Allocation size and `strncat()` length therefore remain valid and bounded by the hostname-only context.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/aaa/mod_authn_socache.c b/modules/aaa/mod_authn_socache.c
index 0e4454a..ecbd1ac 100644
--- a/modules/aaa/mod_authn_socache.c
+++ b/modules/aaa/mod_authn_socache.c
@@ -271,6 +271,9 @@ static const char *construct_key(request_rec *r, const char *context,
         /* FIXME: are we at risk of this blowing up? */
         char *new_context;
         char *slash = strrchr(r->uri, '/');
+        if (slash == NULL) {
+            slash = r->uri;
+        }
         new_context = apr_palloc(r->pool, slash - r->uri +
                                  strlen(r->server->server_hostname) + 1);
         strcpy(new_context, r->server->server_hostname);
```