# getpwent copies oversized YP passwd values

## Classification

High severity out-of-bounds write.

Confidence: certain.

## Affected Locations

`gen/getpwent.c:361`

## Summary

`getpwent()` copies YP passwd map values into the mmap-backed passwd buffer using attacker-controlled `datalen`, but several YP enumeration paths either check the wrong length variable or do not check the value length at all. A malicious YP server can return a short key and oversized passwd value, causing `bcopy(data, pwbuf, datalen)` and `pwbuf[datalen] = '\0'` to write past `pwbuf`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The client is configured to use YP passwd enumeration through `getpwent()`.
- The local passwd database contains a YP inclusion entry such as `+`, `+@group`, or `+user`.
- The YP passwd backend is malicious or attacker-controlled.

## Proof

YP inclusion entries drive `getpwent()` into the vulnerable YP path:

- `+` selects `YPMODE_FULL`.
- `+@group` selects `YPMODE_NETGRP`.
- `+user` selects `YPMODE_USER`.

In these modes, YP APIs return attacker-controlled passwd map data and length:

- `YPMODE_FULL` receives `data` and `datalen` from `yp_first()` or `yp_next()`.
- `YPMODE_NETGRP` receives `data` and `datalen` from `yp_match()`.
- `YPMODE_USER` receives `data` and `datalen` from `yp_match()`.

Before the patch:

- The `yp_first()` branch checked `__ypcurrentlen > buflen`, which is the key length, not the value length.
- The `yp_next()` branch did not check `datalen` before copying.
- The netgroup and user branches repeated the same wrong `__ypcurrentlen > buflen` check.
- All branches then copied `datalen` bytes into `pwbuf` and wrote a terminator at `pwbuf[datalen]`.

Because `pwbuf` comes from `__get_pw_buf()` with fixed size `sizeof(_pw_storage->pwbuf)`, an oversized YP passwd value with an acceptable key length writes outside the mapped passwd buffer.

## Why This Is A Real Bug

The destination size is `buflen`, but the copy and terminator are controlled by `datalen`. Checking `__ypcurrentlen` does not constrain the amount copied because `__ypcurrentlen` is the YP key length. Therefore a malicious YP server can satisfy the existing check with a short key while returning a value larger than `pwbuf`.

The impact is memory corruption in any YP-enabled client process performing passwd enumeration through `getpwent()`.

## Fix Requirement

Validate `datalen` against `buflen` before every `bcopy(data, pwbuf, datalen)` and before the subsequent `pwbuf[datalen] = '\0'`.

The correct bound is `datalen < buflen`, because one additional byte is written for the NUL terminator.

## Patch Rationale

The patch replaces the incorrect `__ypcurrentlen > buflen` checks with `datalen >= buflen` checks in all affected YP enumeration modes. This ensures the value plus terminator fits in `pwbuf`.

The patch also adds the missing `datalen` check to the `yp_next()` path in `YPMODE_FULL`, closing the unchecked continuation case.

Initializing `key` to `NULL` and freeing it on the new `yp_next()` failure path avoids leaking the YP key when rejecting an oversized value after a successful `yp_next()` call.

## Residual Risk

None

## Patch

```diff
diff --git a/gen/getpwent.c b/gen/getpwent.c
index d851711..ace9d33 100644
--- a/gen/getpwent.c
+++ b/gen/getpwent.c
@@ -330,7 +330,7 @@ again:
 	if (__getpwent_has_yppw && (__ypmode != YPMODE_NONE)) {
 		const char *user, *host, *dom;
 		int keylen, datalen, r, s;
-		char *key, *data = NULL;
+		char *key = NULL, *data = NULL;
 
 		if (!__ypdomain)
 			yp_get_default_domain(&__ypdomain);
@@ -342,8 +342,9 @@ again:
 				    &key, &keylen, &data, &datalen);
 				free(__ypcurrent);
 				__ypcurrent = NULL;
-				if (r != 0) {
+				if (r != 0 || datalen >= buflen) {
 					__ypmode = YPMODE_NONE;
+					free(key);
 					free(data);
 					goto again;
 				}
@@ -354,7 +355,7 @@ again:
 				    &__ypcurrent, &__ypcurrentlen,
 				    &data, &datalen);
 				if (r != 0 ||
-				    __ypcurrentlen > buflen) {
+				    datalen >= buflen) {
 					__ypmode = YPMODE_NONE;
 					free(data);
 					goto again;
@@ -376,7 +377,7 @@ again:
 			} else
 				goto again;
 			if (r != 0 ||
-			    __ypcurrentlen > buflen) {
+			    datalen >= buflen) {
 				/*
 				 * if the netgroup is invalid, keep looking
 				 * as there may be valid users later on.
@@ -395,7 +396,7 @@ again:
 				free(name);
 				name = NULL;
 				if (r != 0 ||
-				    __ypcurrentlen > buflen) {
+				    datalen >= buflen) {
 					free(data);
 					goto again;
 				}
```