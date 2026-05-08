# CHAP Username Authentication Log Injection

## Classification

Medium severity log injection.

Confidence: certain.

## Affected Locations

`usr.sbin/npppd/npppd/chap.c:432`

## Summary

An unauthenticated PPP peer can control the CHAP Response Name and include embedded quotes, whitespace, and key/value-looking tokens. The value is copied into `_this->name` and later logged inside a structured authentication log message as `username="%s"` without escaping, allowing forged fields such as `realm=admin` or `logtype=Success` to appear in failed authentication logs.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched.

## Preconditions

- CHAP authentication is started.
- The peer controls the CHAP Response Name field.
- Authentication reaches a failure path that calls `chap_response(..., authok=0, ...)`.

## Proof

`chap_input()` parses the peer-supplied CHAP Response Name, copies it into `namebuf`, NUL-terminates it, assigns `name = namebuf`, and stores it directly in `_this->name` with `strlcpy()`.

On local MD5-CHAP authentication failure, `md5chap_authenticate()` reaches `auth_failed`, calls `chap_send_error()`, and then `chap_response(..., authok=0, ...)`.

Before the patch, `chap_response()` logged `_this->name` directly:

```c
chap_log(_this, LOG_ALERT,
    "logtype=Failure username=\"%s\" realm=%s", _this->name,
    realm_name);
```

A peer-supplied Response Name such as:

```text
bob" realm=admin logtype=Success username="alice
```

could produce an authentication failure log similar to:

```text
... logtype=Failure username="bob" realm=admin logtype=Success username="alice" realm=local
```

This forges additional authentication log fields and obscures failed-login attribution.

## Why This Is A Real Bug

The CHAP Response Name is attacker-controlled before authentication succeeds. The authentication log format uses quoted key/value fields, but the username was interpolated without escaping. Because embedded double quotes and whitespace were preserved by `chap_log()` and `vlog_printf()`, an attacker could break out of the `username="..."` value and inject additional log tokens.

This affects security log integrity and attribution for failed authentication attempts.

## Fix Requirement

Escape or structured-encode the username before writing it into authentication log lines.

The escaped representation must prevent embedded quotes, whitespace, and other special characters from being interpreted as log syntax.

## Patch Rationale

The patch applies `strvis()` to `_this->name` before authentication logging:

```c
char username[4 * MAX_USERNAME_LENGTH + 1];

strvis(username, _this->name, VIS_DQ | VIS_WHITE);
```

`VIS_DQ` escapes double quotes, and `VIS_WHITE` escapes whitespace. The destination buffer is sized for the worst-case visible expansion of the CHAP username plus a NUL terminator.

Both failure and success authentication logs now use the escaped `username` buffer while preserving the original `_this->name` for authentication state and `ppp->username`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/npppd/npppd/chap.c b/usr.sbin/npppd/npppd/chap.c
index 8716eb2..9c37ef5 100644
--- a/usr.sbin/npppd/npppd/chap.c
+++ b/usr.sbin/npppd/npppd/chap.c
@@ -428,6 +428,7 @@ static void
 chap_response(chap *_this, int authok, u_char *pktp, int lpktp)
 {
 	const char *realm_name;
+	char username[4 * MAX_USERNAME_LENGTH + 1];
 
 	CHAP_ASSERT(_this != NULL);
 	CHAP_ASSERT(pktp != NULL);
@@ -437,10 +438,11 @@ chap_response(chap *_this, int authok, u_char *pktp, int lpktp)
 	ppp_output(_this->ppp, PPP_PROTO_CHAP, (authok)? 3 : 4, _this->challid,
 	    pktp, lpktp);
 
+	strvis(username, _this->name, VIS_DQ | VIS_WHITE);
 	realm_name = npppd_ppp_get_realm_name(_this->ppp->pppd, _this->ppp);
 	if (!authok) {
 		chap_log(_this, LOG_ALERT,
-		    "logtype=Failure username=\"%s\" realm=%s", _this->name,
+		    "logtype=Failure username=\"%s\" realm=%s", username,
 		    realm_name);
 		chap_stop(_this);
 		/* Stop the PPP if the authentication is failed. */
@@ -452,7 +454,7 @@ chap_response(chap *_this, int authok, u_char *pktp, int lpktp)
 		    sizeof(_this->ppp->username));
 		chap_log(_this, LOG_INFO,
 		    "logtype=Success username=\"%s\" "
-		    "realm=%s", _this->name, realm_name);
+		    "realm=%s", username, realm_name);
 		chap_stop(_this);
 		/* We change our state to prepare to resend requests. */
 		_this->state = CHAP_STATE_SENT_RESPONSE;
```