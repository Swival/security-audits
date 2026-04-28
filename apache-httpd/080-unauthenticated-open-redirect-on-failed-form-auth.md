# Unauthenticated Open Redirect on Failed Form Auth

## Classification

Medium severity vulnerability: unauthenticated open redirect.

Confidence: certain.

## Affected Locations

`modules/aaa/mod_auth_form.c:1075`

The originally reported location `modules/aaa/mod_auth_form.c:1090` is nearby but points at the later `Cache-Control` handling, not the vulnerable redirect decision.

## Summary

`mod_auth_form` accepts a client-supplied form location field intended for redirect after successful login. In `authenticate_form_authn`, the parsed `sent_loc` value remains populated even when authentication fails. The function later redirects to `sent_loc` without requiring successful authentication, allowing an unauthenticated failed login POST to force a browser redirect to an attacker-controlled URL.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched.

## Preconditions

- Form authentication is enabled with `AuthType form`.
- An unauthenticated client can POST to a protected form-auth endpoint.
- The POST body parser accepts the submitted form.
- The client can submit the configured location field, defaulting to `httpd_location`.
- No valid session or request notes already authenticate the request.
- `AuthFormLoginRequiredLocation` is not configured, or the attacker targets a form-auth location where it is absent.

## Proof

A practical unauthenticated trigger is:

```text
POST /protected-resource HTTP/1.1
Content-Type: application/x-www-form-urlencoded

httpd_username=attacker&httpd_password=wrong&httpd_location=https://evil.example/
```

Execution path:

- `get_form_auth` parses the form body and stores the client-controlled location in `sent_loc`.
- `check_authn` fails because the supplied credentials are invalid.
- `sent_loc` remains set after authentication failure.
- Failure handling reaches the later redirect block.
- The vulnerable code writes `Location: https://evil.example/` and returns `HTTP_MOVED_TEMPORARILY`.

## Why This Is A Real Bug

The `AuthFormLocation` directive describes a redirect target for successful login. The vulnerable path violates that contract by honoring `sent_loc` even when authentication fails.

This is security-relevant because:

- The attacker does not need valid credentials.
- The redirect target is client-controlled.
- Absolute external URLs are accepted.
- The behavior occurs on protected endpoints before authentication succeeds.
- Browsers will follow the `302` response to the attacker-supplied destination.

## Fix Requirement

Only honor the client-supplied form location after successful authentication.

If authentication fails, `sent_loc` must not cause a redirect.

## Patch Rationale

The patch adds an explicit success check before using `sent_loc` in the late redirect block:

```c
if (OK == rv && sent_loc) {
```

This preserves the intended successful-login redirect behavior while preventing failed authentication from triggering an attacker-controlled redirect.

The earlier successful-authentication path already redirects immediately after `check_authn` returns `OK`; the new guard prevents the fallback redirect block from being used after failure.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/aaa/mod_auth_form.c b/modules/aaa/mod_auth_form.c
index d443092..3e35f39 100644
--- a/modules/aaa/mod_auth_form.c
+++ b/modules/aaa/mod_auth_form.c
@@ -1072,7 +1072,7 @@ static int authenticate_form_authn(request_rec * r)
     }
 
     /* did the user ask to be redirected on login success? */
-    if (sent_loc) {
+    if (OK == rv && sent_loc) {
         apr_table_set(r->headers_out, "Location", sent_loc);
         rv = HTTP_MOVED_TEMPORARILY;
     }
```