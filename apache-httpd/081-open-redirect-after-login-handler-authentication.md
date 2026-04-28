# Open Redirect After Login Handler Authentication

## Classification

Medium severity validation gap.

## Affected Locations

`modules/aaa/mod_auth_form.c:1169`

## Summary

`authenticate_form_login_handler()` redirected authenticated users to the submitted form location without validating that the target was local. An attacker who can supply the configured `AuthFormLocation` field during a valid login could cause the post-login response to redirect to an external origin.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The request is handled by `form-login-handler`.
- The request uses `POST`.
- The attacker can supply the configured location form field.
- Valid credentials are submitted, so `check_authn(r, sent_user, sent_pw)` returns `OK`.

## Proof

`get_form_auth()` parses the submitted form and copies the matching configured location field into `sent_loc` without validating scheme, host, or locality.

After successful authentication, `authenticate_form_login_handler()` calls `set_session_auth()` and then directly sets:

```c
apr_table_set(r->headers_out, "Location", sent_loc);
return HTTP_MOVED_TEMPORARILY;
```

A submitted value such as `https://attacker.example/landing` or `//attacker.example/landing` therefore becomes the response `Location` header after a successful login.

## Why This Is A Real Bug

The redirect target is attacker-controlled form input. Authentication gates exploitation, but it does not make the redirect safe: a valid login can still be used to send the browser to an attacker-controlled origin. This enables phishing and post-authentication redirect abuse using the trusted login endpoint.

No source-grounded validation in the affected path restricts `sent_loc` to same-origin or relative URLs. Existing validation around `AuthFormLocation` only validates the configured field name, not the submitted redirect target.

## Fix Requirement

Only redirect to local relative targets, or validate `sent_loc` against a trusted allowlist before setting the `Location` response header.

## Patch Rationale

The patch adds a guard before using `sent_loc` as a redirect target:

```c
if (sent_loc && !ap_is_url(sent_loc) && (sent_loc[0] != '/' || sent_loc[1] != '/')) {
```

This rejects absolute URLs detected by `ap_is_url(sent_loc)` and rejects scheme-relative URLs beginning with `//`. Only non-URL local relative targets are accepted for the login-handler redirect.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/aaa/mod_auth_form.c b/modules/aaa/mod_auth_form.c
index d443092..c7fed42 100644
--- a/modules/aaa/mod_auth_form.c
+++ b/modules/aaa/mod_auth_form.c
@@ -1138,7 +1138,7 @@ static int authenticate_form_login_handler(request_rec * r)
         rv = check_authn(r, sent_user, sent_pw);
         if (OK == rv) {
             set_session_auth(r, sent_user, sent_pw, conf->site);
-            if (sent_loc) {
+            if (sent_loc && !ap_is_url(sent_loc) && (sent_loc[0] != '/' || sent_loc[1] != '/')) {
                 apr_table_set(r->headers_out, "Location", sent_loc);
                 return HTTP_MOVED_TEMPORARILY;
             }
```