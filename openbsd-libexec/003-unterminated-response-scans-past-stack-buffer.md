# Unterminated Response Scans Past Stack Buffer

## Classification

Out-of-bounds read. Severity: medium. Confidence: certain.

## Affected Locations

`login_ldap/login_ldap.c:158`

## Summary

In `response` service mode, `login_ldap` reads attacker-controlled back-channel data into a fixed stack buffer with `read()`, then parses it as a NUL-terminated C string. If the received buffer contains no NUL byte, `strchr(backbuf, '\0')` scans past `backbuf` until it finds a zero byte elsewhere on the stack.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

`login_ldap` runs the `response` service and reads attacker-controlled back-channel data from fd 3.

## Proof

`login_ldap/login_ldap.c` reads raw data into `backbuf`:

```c
n = read(3, backbuf, sizeof(backbuf));
```

`read()` does not append a terminator. The parser then treats `backbuf` as a C string:

```c
else if ((password = strchr(backbuf, '\0')) != NULL)
	password++;
```

A crafted response back-channel payload of `BUFSIZ` non-NUL bytes reaches this path when `backbuf[0] != '\0'`. `strchr()` then continues reading beyond the end of the stack buffer while searching for `'\0'`.

The reproduced ASan harness confirmed a stack-buffer-overflow in the equivalent `strchr()` operation for a full non-NUL read.

## Why This Is A Real Bug

The protocol parser assumes C-string termination on data read from an untrusted byte stream. That assumption is invalid because `read()` returns a byte count and does not NUL-terminate the destination buffer.

The malformed payload is accepted before authentication rejection, so an unauthenticated login attempt can trigger the out-of-bounds stack read under the stated response-service precondition.

## Fix Requirement

The parser must search only within the number of bytes returned by `read()` and must validate that both protocol fields are properly terminated before using `password`.

## Patch Rationale

The patch replaces unbounded `strchr()` parsing with bounded `memchr()` parsing:

```c
if ((password = memchr(backbuf, '\0', n)) != NULL) {
	password++;
	if (memchr(password, '\0', n - (password - backbuf)) == NULL)
		password = NULL;
}
```

This confines the first delimiter search to `n` bytes and then verifies that the password field also has a terminating NUL within the same received buffer. Malformed unterminated messages now produce a protocol error instead of an out-of-bounds read.

## Residual Risk

None

## Patch

`003-unterminated-response-scans-past-stack-buffer.patch`

```diff
diff --git a/login_ldap/login_ldap.c b/login_ldap/login_ldap.c
index 83de3b9..5d612e4 100644
--- a/login_ldap/login_ldap.c
+++ b/login_ldap/login_ldap.c
@@ -152,13 +152,13 @@ main(int argc, char **argv)
 			return 1;
 		}
 
-		/* null challenge */
-		if (backbuf[0] == '\0')
-			password = backbuf + 1;
 		/* skip the first string to get the password */
-		else if ((password = strchr(backbuf, '\0')) != NULL)
+		if ((password = memchr(backbuf, '\0', n)) != NULL) {
 			password++;
-		else
+			if (memchr(password, '\0', n - (password - backbuf)) == NULL)
+				password = NULL;
+		}
+		if (password == NULL)
 			dlog(0, "protocol error on back channel");
 
 	} else if (strcmp(service, "challenge") == 0) {
```