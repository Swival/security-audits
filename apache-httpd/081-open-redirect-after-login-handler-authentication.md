# Open Redirect After Login Handler Authentication

## Classification

Validation gap; severity medium; confidence certain

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

## Practical Exploit Scenario

A SaaS portal exposes its login endpoint at `https://app.example/login` using `mod_auth_form` configured with `SetHandler form-login-handler`. After a successful login the handler redirects users to whatever location they came from, encoded in the form field `httpd_location`. The intent is that intra-site bookmarks and deep links ("you were going to /reports/q4 before being asked to log in") survive the round trip through authentication.

An attacker hosts a lookalike domain `app-example-portal.attacker.example`. They send victims a link like:

```
https://attacker.example/start
```

which loads a page that auto-submits a POST to the real application:

```html
<form method="POST" action="https://app.example/login">
  <input name="httpd_username" value="">
  <input name="httpd_password" value="">
  <input name="httpd_location"
         value="https://app-example-portal.attacker.example/dashboard?token=phishing">
</form>
```

The victim sees a normal login dialog at `app.example` (the form auto-presents because the handler short-circuits to a login page when credentials are empty). The user enters their *real* credentials, which authenticate successfully against the real provider. `set_session_auth` issues a real session cookie scoped to `app.example`. Then the handler immediately writes `Location: https://app-example-portal.attacker.example/dashboard?token=phishing` and returns 302.

The victim's browser, now holding a valid session cookie for `app.example`, lands on the attacker's clone. The clone serves what looks like the real dashboard, prompts for "MFA reverification" or a "security question," and harvests the answers. Because the user just typed correct credentials at the genuine domain and was redirected away, all user-visible cues (TLS lock, recent history, autofill behavior) make the redirect look normal. The attack survives password managers (which already filled the real form), survives MFA on the login step, and uses the trusted domain as a phishing launch pad.

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