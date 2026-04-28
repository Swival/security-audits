# DNS hook argument injection

## Classification

Vulnerability: argument injection in DNS-01 hook invocation.

Severity: medium.

Confidence: certain.

## Affected Locations

`modules/md/md_acme_authz.c:399`

## Summary

`cha_dns_01_setup` builds a DNS-01 hook command line by string-concatenating `dns01_cmd`, the literal `setup`, `authz->domain`, and the DNS token, then passes that string to `apr_tokenize_to_argv`.

Because `authz->domain` comes from the ACME authorization JSON `identifier.value`, whitespace in that value is interpreted as an argument separator before `md_util_exec` runs the configured DNS hook. This changes the hook's argv shape and can alter hook behavior.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the provided source and reproducer evidence.

## Preconditions

- ACME authorization identifier domain contains whitespace.
- DNS-01 is selected for the authorization.
- A DNS-01 hook command is configured through `md->dns01_cmd` or `MD_KEY_CMD_DNS01`.

## Proof

`md_acme_authz_update` assigns the authorization domain directly from the ACME response:

```c
authz->domain = md_json_gets(json, MD_KEY_IDENTIFIER, MD_KEY_VALUE, NULL);
```

`cha_dns_01_setup` then uses that value unquoted in a synthetic command line:

```c
cmdline = apr_psprintf(p, "%s setup %s %s", dns01_cmd, authz->domain, token);
apr_tokenize_to_argv(cmdline, (char***)&argv, p);
md_util_exec(p, argv[0], argv, &exit_code);
```

With an ACME authorization identifier like:

```text
victim.example extra-arg
```

the hook receives arguments equivalent to:

```text
<dns01_cmd> setup victim.example extra-arg <dns-token>
```

instead of:

```text
<dns01_cmd> setup "victim.example extra-arg" <dns-token>
```

`md_util_exec` uses `APR_PROGRAM_ENV`, so shell metacharacter expansion is not involved. The vulnerability is the changed argv boundary caused by whitespace tokenization before execution.

## Why This Is A Real Bug

The affected value is not derived solely from locally validated configured domains at the point of use. It is read from the ACME authorization response and is not revalidated or checked against requested identifiers before DNS hook invocation.

DNS hook scripts commonly parse positional arguments such as:

```text
setup <domain> <token>
```

An attacker-controlled or malicious ACME response containing whitespace in `identifier.value` can shift positional parameters or introduce option-like extra arguments. That can cause the hook to update the wrong DNS record, mis-handle the token, or take unintended script-specific branches.

This is reachable when DNS-01 is offered and selected for the authorization.

## Fix Requirement

Do not construct an executable command line containing untrusted argument data.

Build the argv array directly:

```c
dns01_cmd, "setup", authz->domain, token, NULL
```

and pass that argv array to `md_util_exec`.

## Patch Rationale

The patch removes command-line string construction and removes `apr_tokenize_to_argv` from the DNS-01 setup path.

Before the patch, whitespace inside `authz->domain` was parsed as argv syntax. After the patch, `authz->domain` is placed into a single argv slot regardless of embedded whitespace:

```c
const char * const argv[] = { dns01_cmd, "setup", authz->domain, token, NULL };
rv = md_util_exec(p, dns01_cmd, argv, &exit_code);
```

This preserves the intended DNS hook interface:

```text
argv[0] = dns01_cmd
argv[1] = setup
argv[2] = authz->domain
argv[3] = token
```

The diagnostic log message remains informational only and no longer controls execution semantics.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/md/md_acme_authz.c b/modules/md/md_acme_authz.c
index 9d07052..55eefbe 100644
--- a/modules/md/md_acme_authz.c
+++ b/modules/md/md_acme_authz.c
@@ -423,8 +423,7 @@ static apr_status_t cha_dns_01_setup(md_acme_authz_cha_t *cha, md_acme_authz_t *
                                      const char **psetup_token, apr_pool_t *p)
 {
     const char *token;
-    const char * const *argv;
-    const char *cmdline, *dns01_cmd;
+    const char *dns01_cmd;
     apr_status_t rv;
     int exit_code, notify_server;
     authz_req_ctx ctx;
@@ -457,12 +456,16 @@ static apr_status_t cha_dns_01_setup(md_acme_authz_cha_t *cha, md_acme_authz_t *
         goto out;
     }
 
-    cmdline = apr_psprintf(p, "%s setup %s %s", dns01_cmd, authz->domain, token); 
-    md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, 
-                  "%s: dns-01 setup command: %s", authz->domain, cmdline);
+    {
+        const char * const argv[] = { dns01_cmd, "setup", authz->domain, token, NULL };
 
-    apr_tokenize_to_argv(cmdline, (char***)&argv, p);
-    if (APR_SUCCESS != (rv = md_util_exec(p, argv[0], argv, &exit_code))) {
+        md_log_perror(MD_LOG_MARK, MD_LOG_DEBUG, 0, p, 
+                      "%s: dns-01 setup command: %s setup %s %s", authz->domain,
+                      dns01_cmd, authz->domain, token);
+
+        rv = md_util_exec(p, dns01_cmd, argv, &exit_code);
+    }
+    if (APR_SUCCESS != rv) {
         md_log_perror(MD_LOG_MARK, MD_LOG_WARNING, rv, p, 
                       "%s: dns-01 setup command failed to execute for %s", md->name, authz->domain);
         goto out;
```