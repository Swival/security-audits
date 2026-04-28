# tls-alpn subjectAltName config injection

## Classification

Validation gap, medium severity. Confidence: certain.

## Affected Locations

`modules/md/md_crypt.c:1310`

## Summary

`md_cert_make_tls_alpn_01()` built a subjectAltName extension value with `apr_psprintf("DNS:%s", domain)` and passed it to `X509V3_EXT_conf_nid()` without validating `domain`. OpenSSL/LibreSSL parse comma-separated SAN config syntax, so a domain containing `,DNS:extra.example` is interpreted as multiple SAN entries in the short-lived tls-alpn-01 challenge certificate.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A tls-alpn-01 challenge certificate is created for a domain string that contains comma-separated X509V3 subjectAltName syntax, such as `victim.example,DNS:extra.example`.

## Proof

The affected path constructs:

```c
alts = apr_psprintf(p, "DNS:%s", domain);
add_ext(x, NID_subject_alt_name, alts, p);
```

`add_ext()` passes the string directly to:

```c
X509V3_EXT_conf_nid(NULL, &ctx, nid, (char*)value)
```

OpenSSL/LibreSSL treat commas in `subjectAltName` config as SAN separators. The reproduced local check:

```sh
openssl req -addext 'subjectAltName=DNS:victim.example,DNS:extra.example'
```

produced two SANs:

```text
DNS:victim.example
DNS:extra.example
```

Therefore, `domain = "victim.example,DNS:extra.example"` reaches the same parser as `DNS:victim.example,DNS:extra.example` and creates an unintended additional SAN.

## Why This Is A Real Bug

The tls-alpn-01 certificate creation path accepts a domain string and embeds it into OpenSSL SAN configuration syntax without escaping or validation. Although `md_dns_is_name()` rejects commas elsewhere, normal configured-MDomain sync through `md_reg_sync_finish()` does not necessarily call that validator before domains are saved or used. Public ACME CAs should reject comma-containing DNS identifiers, but a custom or misbehaving ACME server, or another unvalidated authz-domain source, can trigger the vulnerable path.

The resulting certificate is self-signed and short-lived, so this does not directly mint a trusted certificate for the injected SAN. The concrete bug is unintended SAN creation in the local tls-alpn-01 challenge certificate due to OpenSSL config metacharacter injection.

## Fix Requirement

Reject invalid DNS names, including commas and SAN configuration metacharacters, before constructing the `DNS:%s` subjectAltName string for tls-alpn-01 challenge certificates.

## Patch Rationale

The patch validates `domain` with `md_dns_is_name(p, domain, 1)` before calling `mk_x509()` or constructing the SAN extension value. This reuses the existing DNS-name validator that rejects commas and prevents the domain string from being interpreted as OpenSSL subjectAltName configuration syntax.

Initializing `X509 *x` to `NULL` is necessary because validation can now branch to `out` before `mk_x509()` assigns `x`; the cleanup path safely checks `if (!cert && x)`.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/md/md_crypt.c b/modules/md/md_crypt.c
index eef1268..c2a64f5 100644
--- a/modules/md/md_crypt.c
+++ b/modules/md/md_crypt.c
@@ -2073,11 +2073,14 @@ apr_status_t md_cert_make_tls_alpn_01(md_cert_t **pcert, const char *domain,
                                       const char *acme_id, md_pkey_t *pkey, 
                                       apr_interval_time_t valid_for, apr_pool_t *p)
 {
-    X509 *x;
+    X509 *x = NULL;
     md_cert_t *cert = NULL;
     const char *alts;
     apr_status_t rv;
 
+    if (!md_dns_is_name(p, domain, 1)) {
+        rv = APR_EINVAL; goto out;
+    }
     if (APR_SUCCESS != (rv = mk_x509(&x, pkey, "tls-alpn-01-challenge", valid_for, p))) goto out;
     
     /* add the domain as alt name */
```