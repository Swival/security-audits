# subjectAltName Config Injection via Comma

## Classification

Validation gap, medium severity.

Confidence: certain.

## Affected Locations

`modules/md/md_crypt.c:1091`

Additional reproduced flow locations:

`modules/md/mod_md.c:998`

`modules/md/md_reg.c:1019`

`modules/md/mod_md_config.c:359`

`modules/md/md_acme_drive.c:765`

`modules/md/md_acme_drive.c:377`

`modules/md/md_acme_order.c:293`

## Summary

Configured managed-domain names containing commas were accepted and later interpolated into OpenSSL `subjectAltName` configuration strings as `DNS:%s`. Because OpenSSL treats commas in this configuration format as SAN separators, one configured domain string could inject additional SAN entries into CSRs and self-signed fallback certificates.

The patch rejects comma-containing domain values before constructing the `subjectAltName` extension.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the provided source and patch evidence.

## Preconditions

A configured domain string contains a comma.

Example shape:

```text
good.example,DNS:evil.example
```

## Proof

`alt_names()` in `modules/md/md_crypt.c` built one comma-separated OpenSSL extension configuration string:

```c
alts = apr_psprintf(p, "%s%sDNS:%s", alts, sep, domain);
sep = ",";
```

Domain strings from the managed-domain array reached this function without comma escaping or rejection. `sk_add_alt_names()` then passed the resulting string to:

```c
X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, ...)
```

OpenSSL parses commas as `subjectAltName` entry separators. Therefore a single configured domain value containing `,DNS:evil.example` is parsed as more than one SAN entry.

The reproduced path confirms reachability:

- Config parsing lowercases and stores names via `add_domain_name()` without rejecting commas.
- Sync finish writes the managed domain through `md_save()` without `check_values()`.
- Renewal derives `ad->domains` from `ad->md->domains`.
- CSR creation calls `md_cert_req_create()`, which invokes the vulnerable SAN construction.

Self-signed certificate creation also used the same `alt_names()` output when adding `NID_subject_alt_name`.

## Why This Is A Real Bug

The code invariant should be: one configured domain string produces one `DNS` SAN entry.

That invariant was violated because configuration syntax metacharacters from the domain string were embedded into OpenSSL’s SAN configuration format without validation or encoding. This allowed a comma inside one domain string to alter the structure of the generated SAN extension.

Practical public-CA impact is constrained because ACME order identifiers are created from the same configured domain strings, so a public CA should normally reject invalid DNS identifiers before finalization. However, the bug remains real in this codebase because fallback/self-signed certificates can directly contain injected SANs, and CSR generation itself can encode SANs not corresponding one-to-one with configured domains.

## Fix Requirement

Reject commas in domain names before using them in OpenSSL `subjectAltName` configuration strings, or replace string-based SAN construction with OpenSSL `GENERAL_NAME` APIs.

## Patch Rationale

The patch implements the minimal safe validation approach:

- `alt_names()` now returns `NULL` if any domain contains `,`.
- `sk_add_alt_names()` detects `NULL` and returns `APR_EINVAL` before calling `X509V3_EXT_conf_nid`.
- `md_cert_self_sign()` also checks for `NULL` before calling `add_ext`.

This closes both vulnerable consumers of `alt_names()` shown in the affected source: CSR SAN extension creation and self-signed certificate SAN extension creation.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/md/md_crypt.c b/modules/md/md_crypt.c
index eef1268..6df9ef5 100644
--- a/modules/md/md_crypt.c
+++ b/modules/md/md_crypt.c
@@ -1768,6 +1768,9 @@ static const char *alt_names(apr_array_header_t *domains, apr_pool_t *p)
     
     for (i = 0; i < domains->nelts; ++i) {
         domain = APR_ARRAY_IDX(domains, i, const char *);
+        if (strchr(domain, ',')) {
+            return NULL;
+        }
         alts = apr_psprintf(p, "%s%sDNS:%s", alts, sep, domain);
         sep = ",";
     }
@@ -1806,8 +1809,13 @@ static apr_status_t sk_add_alt_names(STACK_OF(X509_EXTENSION) *exts,
 {
     if (domains->nelts > 0) {
         X509_EXTENSION *x;
+        const char *alts;
         
-        x = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, (char*)alt_names(domains, p));
+        alts = alt_names(domains, p);
+        if (!alts) {
+            return APR_EINVAL;
+        }
+        x = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, (char*)alts);
         if (NULL == x) {
             return APR_EGENERAL;
         }
@@ -2017,6 +2025,7 @@ apr_status_t md_cert_self_sign(md_cert_t **pcert, const char *cn,
 {
     X509 *x;
     md_cert_t *cert = NULL;
+    const char *alts;
     apr_status_t rv;
     
     assert(domains);
@@ -2024,7 +2033,11 @@ apr_status_t md_cert_self_sign(md_cert_t **pcert, const char *cn,
     if (APR_SUCCESS != (rv = mk_x509(&x, pkey, cn, valid_for, p))) goto out;
     
     /* add the domain as alt name */
-    if (APR_SUCCESS != (rv = add_ext(x, NID_subject_alt_name, alt_names(domains, p), p))) {
+    alts = alt_names(domains, p);
+    if (!alts) {
+        rv = APR_EINVAL; goto out;
+    }
+    if (APR_SUCCESS != (rv = add_ext(x, NID_subject_alt_name, alts, p))) {
         md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "%s: set alt_name ext", cn);
         goto out;
     }
```