# Negotiate auth error is treated as success

## Classification

security_control_failure / fail-open authentication. Severity: medium. Confidence: certain.

## Affected Locations

- `lib/http_negotiate.c:200` (`Curl_input_negotiate` invocation in `Curl_output_negotiate`)
- `lib/http_negotiate.c:201` (special-case `CURLE_AUTH_ERROR -> CURLE_OK` branch)
- `lib/vauth/spnego_gssapi.c` initial-token failure paths returning `CURLE_AUTH_ERROR`

## Summary

`Curl_output_negotiate()` converts an initial HTTP Negotiate authentication backend failure into success. If `Curl_input_negotiate()` returns `CURLE_AUTH_ERROR` before a Negotiate context exists, the old code sets `authp->done = TRUE` and returns `CURLE_OK`. The request can then continue without an `Authorization: Negotiate ...` header while authentication is marked complete.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- The client enables HTTP Negotiate authentication for the server.
- The peer advertises `Negotiate` authentication.
- Initial SPNEGO/GSSAPI/SSPI token creation fails with `CURLE_AUTH_ERROR` before a usable context or token is produced.

## Proof

`Curl_output_negotiate()` obtains the Negotiate context and clears `authp->done`.

When no context exists, it calls:

```c
result = Curl_input_negotiate(data, conn, proxy, "Negotiate");
```

Practical initial-token failure paths exist in the SPNEGO backend, including `lib/vauth/spnego_gssapi.c:117`, `lib/vauth/spnego_gssapi.c:162`, and `lib/vauth/spnego_gssapi.c:187`, which can return `CURLE_AUTH_ERROR` before a usable token is produced.

The vulnerable branch then treats that authentication failure as success:

```c
if(result == CURLE_AUTH_ERROR) {
  authp->done = TRUE;
  return CURLE_OK;
}
```

Because this return occurs before `data->req.hd_auth` or `data->req.hd_proxy_auth` is assigned, the next request can be built without a Negotiate authorization header while the auth state reports completion.

## Why This Is A Real Bug

An authentication control must fail closed when token generation fails. The affected branch does the opposite: it marks authentication as done and returns success on `CURLE_AUTH_ERROR`.

This creates a deterministic fail-open path for HTTP Negotiate. A server advertising Negotiate can cause the client-side authentication setup to fail before context creation, after which curl proceeds as if authentication completed. That behavior bypasses the intended error handling and can send a request unauthenticated.

## Fix Requirement

Propagate `CURLE_AUTH_ERROR` from `Curl_input_negotiate()` instead of marking `authp->done` and returning `CURLE_OK`.

## Patch Rationale

The patch removes the special-case conversion of `CURLE_AUTH_ERROR` into success. `Curl_output_negotiate()` now handles all nonzero results from `Curl_input_negotiate()` uniformly:

```c
if(result)
  return result;
```

This preserves fail-closed behavior for Negotiate setup failures and prevents the request from continuing without an authorization header after an authentication backend error.

The branch being removed was added intentionally to preserve pre-7.64 behavior. Callers who relied on a transparent fallback to unauthenticated when GSSAPI/SSPI initialization fails will now see the underlying `CURLE_AUTH_ERROR`. That is the more conservative behavior for a security-sensitive option that the caller explicitly opted into.

## Residual Risk

A small behavior change: applications that previously relied on Negotiate setup failures silently producing an unauthenticated request will now observe `CURLE_AUTH_ERROR` and must handle it (e.g., retry with `CURLAUTH_NONE` or surface to the user).

## Patch

```diff
diff --git a/lib/http_negotiate.c b/lib/http_negotiate.c
index b037bb2ec9..4702ac0837 100644
--- a/lib/http_negotiate.c
+++ b/lib/http_negotiate.c
@@ -198,13 +198,7 @@ CURLcode Curl_output_negotiate(struct Curl_easy *data,
     }
     if(!neg_ctx->context) {
       result = Curl_input_negotiate(data, conn, proxy, "Negotiate");
-      if(result == CURLE_AUTH_ERROR) {
-        /* negotiate auth failed, let's continue unauthenticated to stay
-         * compatible with the behavior before curl-7_64_0-158-g6c6035532 */
-        authp->done = TRUE;
-        return CURLE_OK;
-      }
-      else if(result)
+      if(result)
         return result;
     }

     result = Curl_auth_create_spnego_message(neg_ctx, &base64, &len);
```