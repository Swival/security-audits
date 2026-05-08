# domain slash check scans pointer bytes

## Classification

Path traversal; high severity.

## Affected Locations

`usr.sbin/ypbind/ypbind.c:139`

## Summary

`ypbindproc_domain_2x()` attempts to reject domains containing `/`, but calls `strchr((char *)argp, '/')` on the address of the `domainname` argument object rather than the decoded attacker-controlled string `*argp`. As a result, slash-containing domain names can pass validation and be used to construct paths under `/var/yp/binding`, enabling `../` traversal before `unlink(path)`.

## Provenance

Reproduced and patched from a verified Swival Security Scanner finding: https://swival.dev

Confidence: certain.

## Preconditions

- `ypbind` is reachable over RPC.
- The attacker invokes unauthenticated `YPBINDPROC_DOMAIN`.
- The supplied domain is absent from `ypbindlist`.
- The in-memory bytes of the `argp` pointer object do not contain `/`.

## Proof

`ypbindprog_2()` exposes `YPBINDPROC_DOMAIN` without the authentication checks applied to `YPBINDPROC_SETDOM`.

For `YPBINDPROC_DOMAIN`, the decoded domain is passed to `ypbindproc_domain_2x()` as `domainname *argp`. The function later treats the actual domain string as `*argp`, including:

- `strcmp(ypdb->dom_domain, *argp)`
- `strlcpy(ypdb->dom_domain, *argp, sizeof ypdb->dom_domain)`

However, the slash rejection checks the wrong object:

```c
if (strchr((char *)argp, '/'))
	return NULL;
```

This scans bytes at the pointer variable address, not the attacker-controlled string. If the supplied domain is absent and the list count is below 100, the code copies `*argp` into `ypdb->dom_domain`, formats it into a binding path, and unlinks it:

```c
strlcpy(ypdb->dom_domain, *argp, sizeof ypdb->dom_domain);
snprintf(path, sizeof path, "%s/%s.%d", BINDINGDIR,
    ypdb->dom_domain, (int)ypdb->dom_vers);
unlink(path);
```

A domain such as `../../../etc/passwd` produces:

```text
/var/yp/binding/../../../etc/passwd.2
```

That path resolves outside `BINDINGDIR`, with the fixed `.2` suffix constraint.

## Why This Is A Real Bug

The vulnerable check is intended to prevent filesystem path separators in domain names, but it does not inspect the domain string that is later copied into `dom_domain` and interpolated into filesystem paths. The later correct slash check in `rpc_received()` does not protect this earlier `unlink()` path in `ypbindproc_domain_2x()`.

Impact is an unauthenticated remote RPC client causing privileged `ypbind` to unlink attacker-selected filesystem paths, constrained by the appended `.2` suffix and process privileges.

## Fix Requirement

Validate the decoded domain string `*argp` for `/` before copying it into `dom_domain` or constructing any filesystem path from it.

## Patch Rationale

The patch changes the slash check from the pointer object to the actual decoded domain string. This preserves the intended validation behavior and blocks `../` path components before the domain is used in `snprintf()` for `/var/yp/binding/%s.%d`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ypbind/ypbind.c b/usr.sbin/ypbind/ypbind.c
index d8ca66d..ce2674e 100644
--- a/usr.sbin/ypbind/ypbind.c
+++ b/usr.sbin/ypbind/ypbind.c
@@ -136,7 +136,7 @@ ypbindproc_domain_2x(SVCXPRT *transp, domainname *argp, CLIENT *clnt)
 	time_t now;
 	int count = 0;
 
-	if (strchr((char *)argp, '/'))
+	if (strchr(*argp, '/'))
 		return NULL;
 
 	memset(&res, 0, sizeof(res));
```