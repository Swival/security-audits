# commonName accepted despite DNS SAN

## Classification

Logic error, medium severity. Confidence: certain.

## Affected Locations

`modules/ssl/ssl_util_ssl.c:381`

## Summary

Certificate hostname verification collected both `dNSName` SAN entries and subject `commonName` entries into the same ID list. `modssl_X509_match_name()` then accepted any matching ID, so a certificate with nonmatching DNS SANs could still be accepted if its CN matched the requested name.

## Provenance

Verified from provided source, reproduced control flow, and patch evidence.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Certificate contains at least one `dNSName` subjectAltName.
- None of the DNS SAN values match the requested hostname.
- The certificate subject contains a `commonName` that does match the requested hostname.
- Name verification reaches `modssl_X509_match_name()`.

## Proof

`getIDs()` first calls `modssl_X509_getSAN(p, x509, GEN_DNS, NULL, -1, ids)` to populate `ids` with DNS SAN entries.

Before the patch, `getIDs()` then unconditionally scanned subject CNs:

```c
subj = X509_get_subject_name(x509);
while ((i = X509_NAME_get_index_by_NID(subj, NID_commonName, i)) != -1) {
    APR_ARRAY_PUSH(*ids, const char *) =
        modssl_X509_NAME_ENTRY_to_string(p, X509_NAME_get_entry(subj, i), 0);
}
```

`modssl_X509_match_name()` iterates all collected IDs and accepts a case-insensitive match:

```c
!strcasecmp(id[i], name)
```

Therefore, when DNS SANs exist but do not match, a matching CN is still appended and can satisfy hostname verification.

The path is reachable from SSL proxy peer hostname checks through `modules/ssl/ssl_engine_io.c:1335` when peer-name checking is enabled and `hostname_note` is present.

## Why This Is A Real Bug

Modern certificate name validation gives DNS SAN identities precedence over CN fallback. CN fallback is only valid when no relevant DNS SAN is present. The original logic violates that rule by treating CN as an additional valid identity even when DNS SAN identities exist.

This can cause an upstream TLS peer certificate to be accepted for a hostname based on CN despite explicit DNS SAN identities that do not authorize that hostname.

## Fix Requirement

Only append subject `commonName` entries when no `dNSName` SAN entries were found.

## Patch Rationale

The patch wraps CN extraction in `if (apr_is_empty_array(*ids))`, so CN fallback occurs only when the DNS SAN collection produced no entries.

This preserves existing CN fallback behavior for certificates without DNS SANs while enforcing SAN-over-CN precedence for certificates that do contain DNS SANs.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/ssl/ssl_util_ssl.c b/modules/ssl/ssl_util_ssl.c
index 8bd9c8a..039e51f 100644
--- a/modules/ssl/ssl_util_ssl.c
+++ b/modules/ssl/ssl_util_ssl.c
@@ -373,10 +373,12 @@ static BOOL getIDs(apr_pool_t *p, X509 *x509, apr_array_header_t **ids)
     }
 
     /* Second, the CN-IDs (commonName attributes in the subject DN) */
-    subj = X509_get_subject_name(x509);
-    while ((i = X509_NAME_get_index_by_NID(subj, NID_commonName, i)) != -1) {
-        APR_ARRAY_PUSH(*ids, const char *) = 
-            modssl_X509_NAME_ENTRY_to_string(p, X509_NAME_get_entry(subj, i), 0);
+    if (apr_is_empty_array(*ids)) {
+        subj = X509_get_subject_name(x509);
+        while ((i = X509_NAME_get_index_by_NID(subj, NID_commonName, i)) != -1) {
+            APR_ARRAY_PUSH(*ids, const char *) = 
+                modssl_X509_NAME_ENTRY_to_string(p, X509_NAME_get_entry(subj, i), 0);
+        }
     }
 
     return apr_is_empty_array(*ids) ? FALSE : TRUE;
```