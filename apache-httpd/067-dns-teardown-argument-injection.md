# DNS teardown argument injection

## Classification

Vulnerability, medium severity.

## Affected Locations

`modules/md/md_acme_authz.c:466`

## Summary

The DNS-01 teardown path constructed a single command string with an ACME-provided authorization domain and then tokenized that string into `argv`. When DNS-01 teardown v2 was enabled, whitespace in the domain was preserved, so a domain value such as `victim.example --zone attacker` became additional arguments to the configured DNS hook command.

This is argument injection into the hook process, not shell metacharacter execution.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- DNS-01 teardown v2 is enabled through `DNS01_VERSION=2`.
- The ACME authorization response contains an identifier value with whitespace.
- That identifier value is stored as `authz->domain`.
- A DNS-01 hook command is configured.

## Proof

`md_acme_authz_update` stores the ACME JSON identifier value directly as `authz->domain`.

DNS-01 setup returns a teardown token in the form:

```text
dns-01:<domain> <token>
```

During teardown, `md_acme_authz_teardown` splits only at `:`, leaving the remaining value as the `domain` argument passed to `cha_dns_01_teardown`.

For legacy teardown, `cha_dns_01_teardown` truncates the value at the first space. However, when `DNS01_VERSION` is `"2"`, that truncation is skipped. The vulnerable code then formats:

```c
"%s teardown %s"
```

and passes the result to `apr_tokenize_to_argv`.

Therefore, with an ACME authorization domain like:

```text
victim.example --zone attacker
```

the hook receives arguments equivalent to:

```text
dns-hook
teardown
victim.example
--zone
attacker
<dns-token>
```

The execution path uses `md_util_exec` with `APR_PROGRAM_ENV`, so the impact is attacker-controlled extra argv elements or shifted positional arguments to the DNS hook.

## Why This Is A Real Bug

The vulnerable value originates from the ACME server response and is not revalidated before command construction. Although local configured managed-domain names are validated elsewhere, this teardown path uses the ACME-supplied `authz->domain`.

The command is not executed through a shell, but the configured DNS hook receives a modified argument vector. Hooks commonly parse options and positional arguments, so injected whitespace can alter hook behavior, change option values, or shift the DNS token argument.

## Fix Requirement

The teardown implementation must not concatenate untrusted domain data into a tokenized command line. It must preserve the configured command parsing while appending `teardown` and the domain as distinct argv elements.

## Patch Rationale

The patch tokenizes only the configured DNS-01 command, counts its existing argv elements, allocates a new argv array, copies the command argv, and appends:

```text
teardown
<domain>
```

as separate argv entries.

This preserves existing support for configured commands with arguments while preventing whitespace inside the domain from being reparsed as additional hook arguments.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/md/md_acme_authz.c b/modules/md/md_acme_authz.c
index 9d07052..d8e6336 100644
--- a/modules/md/md_acme_authz.c
+++ b/modules/md/md_acme_authz.c
@@ -501,10 +501,11 @@ static apr_status_t cha_dns_01_teardown(md_store_t *store, const char *domain, c
                                         apr_table_t *env, apr_pool_t *p)
 {
     const char * const *argv;
-    const char *cmdline, *dns01_cmd, *dns01v;
+    const char **teardown_argv;
+    const char *dns01_cmd, *dns01v;
     char *tmp, *s;
     apr_status_t rv;
-    int exit_code;
+    int argc, exit_code;
     
     (void)store;
 
@@ -528,9 +529,16 @@ static apr_status_t cha_dns_01_teardown(md_store_t *store, const char *domain, c
         }
     }
 
-    cmdline = apr_psprintf(p, "%s teardown %s", dns01_cmd, domain); 
-    apr_tokenize_to_argv(cmdline, (char***)&argv, p);
-    if (APR_SUCCESS != (rv = md_util_exec(p, argv[0], argv, &exit_code)) || exit_code) {
+    apr_tokenize_to_argv(dns01_cmd, (char***)&argv, p);
+    argc = 0;
+    while (argv[argc]) {
+        ++argc;
+    }
+    teardown_argv = apr_pcalloc(p, (argc + 3) * sizeof(*teardown_argv));
+    memcpy(teardown_argv, argv, argc * sizeof(*teardown_argv));
+    teardown_argv[argc++] = "teardown";
+    teardown_argv[argc++] = domain;
+    if (APR_SUCCESS != (rv = md_util_exec(p, teardown_argv[0], teardown_argv, &exit_code)) || exit_code) {
         md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, p, 
                       "%s: dns-01 teardown command failed (exit code=%d) for %s",
                       md->name, exit_code, domain);
```