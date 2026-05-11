# Unauthenticated LDAP URL Uses Ambient Windows Credentials

## Classification

Information disclosure, high severity, confidence certain.

## Affected Locations

`lib/ldap.c:197` (`ldap_win_bind_auth` fallback that sets `method = LDAP_AUTH_NEGOTIATE`)

## Summary

On Windows builds using WinLDAP and Windows SSPI, an unauthenticated LDAP URL can trigger SSPI authentication with the current Windows user credentials. An attacker who can cause curl/libcurl to fetch an attacker-controlled `ldap://` or `ldaps://` URL can receive Negotiate/NTLM authentication material from the process account.

## Provenance

Identified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Build enables `USE_WIN32_LDAP`.
- Build enables `USE_WINDOWS_SSPI`.
- The target URL is LDAP/LDAPS and does not provide explicit credentials.
- An attacker controls the LDAP server selected by the URL.

## Proof

`ldap_do()` only assigns LDAP credentials when `data->state.aptr.user` exists. For unauthenticated LDAP URLs, both `user` and `passwd` remain `NULL`.

The URL-selected host is then used to create the LDAP connection via `ldap_init()` or `ldap_sslinit()`, and the code calls:

```c
rc = ldap_win_bind(data, server, user, passwd);
```

Inside `ldap_win_bind()`, the BASIC bind path is skipped unless both credentials exist and `CURLAUTH_BASIC` is enabled. With `USE_WINDOWS_SSPI`, execution falls into:

```c
rc = ldap_win_bind_auth(server, user, passwd, data->set.httpauth);
```

Before the patch, `ldap_win_bind_auth()` handled the no-credential path by forcing Negotiate:

```c
else {
  /* proceed with current user credentials */
  method = LDAP_AUTH_NEGOTIATE;
  rc = ldap_bind_s(server, NULL, NULL, method);
}
```

The in-code comment confirms the behavior: this proceeds with current user credentials. Because the LDAP server is selected from the URL, an attacker-controlled LDAP endpoint can induce ambient Windows SSPI authentication.

## Why This Is A Real Bug

An unauthenticated URL should not cause implicit use of ambient OS credentials. The vulnerable path sends Windows SSPI authentication to a URL-selected server without explicit credentials or an authentication opt-in from the caller. Negotiate/NTLM tokens are reusable authentication material and their disclosure to an attacker-controlled LDAP server is a high-impact information disclosure.

## Fix Requirement

Do not perform Windows SSPI LDAP bind with ambient credentials unless an explicit SSPI authentication method was requested. In particular, an unauthenticated LDAP URL with no selected SSPI method must not be upgraded to `LDAP_AUTH_NEGOTIATE`.

## Patch Rationale

The patch changes the fallback branch in `ldap_win_bind_auth()` from unconditional ambient Negotiate authentication to only binding when an SSPI method was explicitly selected:

```diff
-  else {
+  else if(method) {
     /* proceed with current user credentials */
-    method = LDAP_AUTH_NEGOTIATE;
     rc = ldap_bind_s(server, NULL, NULL, method);
   }
```

This preserves SSPI behavior when `authflags` selected a supported method, while preventing credential-free LDAP URLs from silently forcing `LDAP_AUTH_NEGOTIATE`.

## Residual Risk

None

## Patch

`009-unauthenticated-ldap-url-uses-ambient-windows-credentials.patch`

```diff
diff --git a/lib/ldap.c b/lib/ldap.c
index 3705754476..9247f4111a 100644
--- a/lib/ldap.c
+++ b/lib/ldap.c
@@ -194,9 +194,8 @@ static ULONG ldap_win_bind_auth(LDAP *server, const char *user,
       rc = LDAP_NO_MEMORY;
     }
   }
-  else {
+  else if(method) {
     /* proceed with current user credentials */
-    method = LDAP_AUTH_NEGOTIATE;
     rc = ldap_bind_s(server, NULL, NULL, method);
   }
   return rc;
```