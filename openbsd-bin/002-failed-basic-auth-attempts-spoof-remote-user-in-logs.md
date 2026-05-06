# Failed Basic-Auth Attempts Spoof Remote User In Logs

## Classification

Repudiation, low severity. Confidence: certain.

## Affected Locations

`httpd/server_http.c:151`

## Summary

Failed HTTP Basic authentication attempts can cause access logs to record an attacker-chosen remote username. `server_http_authenticate()` stores the decoded Basic username in `clt->clt_remote_user` before validating the password, and the 401 failure path logs that field.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A logged location requires Basic authentication.

## Proof

An unauthenticated client sends a request to a Basic-auth protected logged location with:

```http
Authorization: Basic <base64("chosen_user:badpass")>
```

Execution path:

- `server_response()` calls `server_http_authenticate()` for `SRVFLAG_AUTH` locations.
- `server_http_authenticate()` decodes the Basic credentials and assigns `clt->clt_remote_user = strdup(clt_user)` before opening the htpasswd file or checking `crypt_checkpass()`.
- If no htpasswd entry matches, or if `crypt_checkpass()` fails, authentication returns `-1`.
- `server_response()` immediately calls `server_abort_http(clt, 401, ...)`.
- `server_abort_http()` calls `server_log_http()` before closing the request.
- `server_log_http()` emits `clt->clt_remote_user` in common, combined, and forwarded log formats.

Result: the 401 access-log entry for a failed authentication attempt is attributed to `chosen_user`.

## Why This Is A Real Bug

Access logs should not attribute unauthenticated requests to an asserted username unless that identity has been verified. Here, attacker-controlled Basic username input is promoted to the authenticated remote-user field before password verification. Because the failure path logs that field, audit records for denied requests can be forged with arbitrary usernames.

## Fix Requirement

Set `clt_remote_user` only after `crypt_checkpass()` succeeds. Failed authentication attempts must leave `clt_remote_user` unset so access logs record `-` or another unauthenticated marker.

## Patch Rationale

The patch removes the early assignment of `clt->clt_remote_user` after Basic credential parsing and moves it into the successful `crypt_checkpass()` branch. This preserves existing behavior for valid credentials while preventing failed credentials from populating the authenticated username used by logging.

## Residual Risk

None

## Patch

```diff
diff --git a/httpd/server_http.c b/httpd/server_http.c
index b01e018..32649ab 100644
--- a/httpd/server_http.c
+++ b/httpd/server_http.c
@@ -153,8 +153,6 @@ server_http_authenticate(struct server_config *srv_conf, struct client *clt)
 
 	clt_user = decoded;
 	*clt_pass++ = '\0';
-	if ((clt->clt_remote_user = strdup(clt_user)) == NULL)
-		goto done;
 
 	if ((fp = fopen(auth->auth_htpasswd, "r")) == NULL)
 		goto done;
@@ -179,6 +177,8 @@ server_http_authenticate(struct server_config *srv_conf, struct client *clt)
 
 		if (crypt_checkpass(clt_pass, pass) == 0) {
 			explicit_bzero(line, linelen);
+			if ((clt->clt_remote_user = strdup(clt_user)) == NULL)
+				goto done;
 			ret = 0;
 			break;
 		}
```