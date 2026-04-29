# HTTP GET Bypasses Anonymous Prelogin Controls

## Classification

Policy bypass; high severity.

## Affected Locations

`prelogin.c:205`

## Summary

When FTP parsing is disabled and HTTP is enabled, an unauthenticated HTTP `GET` is converted into synthesized anonymous FTP credentials and passed directly to the password/login path. This skips `handle_user_command()`, which is the prelogin path that enforces anonymous TLS restrictions and userlist denial before authentication proceeds.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- HTTP support is enabled.
- FTP parser is disabled.
- Anonymous userlist policy or anonymous TLS prelogin policy is configured.
- For the directly reproduced impact: `ssl_enable=YES` and `force_anon_logins_ssl=YES`.

## Proof

`parse_username_password()` dispatches HTTP mode `GET` requests directly to `handle_get()` when `tunable_http_enable` is active.

`handle_get()` then:

- sets `p_sess->is_http = 1`;
- copies the requested URL into `p_sess->http_get_arg`;
- sets `p_sess->user_str` to `FTP`;
- sets `p_sess->ftp_arg_str` to `<http>`;
- calls `handle_pass_command()` directly.

That path bypasses `handle_user_command()`, where anonymous prelogin policy is enforced:

- anonymous SSL rejection when encrypted anonymous sessions are disallowed;
- plaintext anonymous rejection when `tunable_force_anon_logins_ssl` is enabled;
- userlist denial checks before login.

After the bypass, `handle_pass_command()` proceeds to `vsf_one_process_login()` or `vsf_two_process_login()`. The reproduced path shows `handle_login()` recognizing `FTP` as anonymous, followed by `process_post_login()` routing HTTP sessions to `handle_http()`.

A remote unauthenticated client can therefore send plaintext:

```http
GET /file HTTP/1.1
```

and reach anonymous HTTP content even when plaintext anonymous FTP login would be rejected before password entry by `force_anon_logins_ssl=YES`.

## Why This Is A Real Bug

The HTTP `GET` path synthesizes the same anonymous identity used by FTP anonymous login, but does not execute the prelogin checks that FTP anonymous login requires. The security decision is therefore dependent on protocol syntax rather than the effective login identity.

This creates a real policy bypass because the server can be configured to require SSL for anonymous logins, yet an unauthenticated plaintext HTTP `GET` can still reach the login backend and post-login HTTP handler.

The userlist portion is less clean in the reproduced configuration because the userlist file is loaded in the two-process/local-user path while HTTP requires one-process mode. The TLS anonymous prelogin policy bypass is directly supported by the shown code and reproduced behavior.

## Fix Requirement

HTTP anonymous setup must enforce the same anonymous prelogin controls as FTP anonymous login before calling `handle_pass_command()`.

Acceptable fixes are:

- route the synthesized HTTP anonymous user through `handle_user_command()`; or
- duplicate the anonymous TLS and userlist prelogin checks in `handle_get()` before password/login dispatch.

## Patch Rationale

The patch adds the missing anonymous prelogin checks to `handle_get()` after setting `user_str` to `FTP` and before setting the synthesized password and calling `handle_pass_command()`.

The added checks mirror the relevant anonymous controls from `handle_user_command()`:

- reject encrypted anonymous sessions when anonymous SSL is not allowed;
- reject plaintext anonymous sessions when anonymous SSL is required;
- enforce configured userlist denial policy;
- preserve login delay, login failure accounting, and `user_str` cleanup behavior on denial.

This keeps HTTP anonymous behavior aligned with FTP anonymous prelogin policy while minimizing control-flow changes.

## Residual Risk

None

## Patch

```diff
diff --git a/prelogin.c b/prelogin.c
index f9e63ba..4ccc5ae 100644
--- a/prelogin.c
+++ b/prelogin.c
@@ -204,6 +204,33 @@ handle_get(struct vsf_session* p_sess)
   p_sess->is_http = 1;
   str_copy(&p_sess->http_get_arg, &p_sess->ftp_arg_str);
   str_alloc_text(&p_sess->user_str, "FTP");
+  if (p_sess->control_use_ssl && !tunable_allow_anon_ssl &&
+      !tunable_force_anon_logins_ssl)
+  {
+    vsf_cmdio_write(
+      p_sess, FTP_LOGINERR, "Anonymous sessions may not use encryption.");
+    str_empty(&p_sess->user_str);
+    return;
+  }
+  if (tunable_ssl_enable && !p_sess->control_use_ssl &&
+      tunable_force_anon_logins_ssl)
+  {
+    vsf_cmdio_write_exit(
+      p_sess, FTP_LOGINERR, "Anonymous sessions must use encryption.", 1);
+  }
+  if (tunable_userlist_enable)
+  {
+    int located = str_contains_line(&p_sess->userlist_str, &p_sess->user_str);
+    if ((located && tunable_userlist_deny) ||
+        (!located && !tunable_userlist_deny))
+    {
+      check_login_delay();
+      vsf_cmdio_write(p_sess, FTP_LOGINERR, "Permission denied.");
+      check_login_fails(p_sess);
+      str_empty(&p_sess->user_str);
+      return;
+    }
+  }
   str_alloc_text(&p_sess->ftp_arg_str, "<http>");
   handle_pass_command(p_sess);
 }
```