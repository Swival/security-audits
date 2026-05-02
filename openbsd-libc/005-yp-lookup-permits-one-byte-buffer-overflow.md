# YP lookup permits one-byte buffer overflow

## Classification

Out-of-bounds write. Severity: high. Confidence: certain.

## Affected Locations

`gen/getpwent.c:650`

## Summary

`__yppwlookup()` accepts YP passwd map values whose length exactly equals the caller-supplied reentrant lookup buffer length. It then copies that many bytes into the buffer and appends a NUL terminator at `buf[ypcurrentlen]`, causing a deterministic one-byte write past the end of `buf`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- YP support is enabled.
- The local passwd database enables YP lookup.
- A caller uses `getpwnam_r()` or `getpwuid_r()` with an attacker-sized buffer.
- A malicious or compromised YP server controls the returned passwd map value length.

## Proof

`getpwnam_r()` passes the caller-provided `buf` and `buflen` into `getpwnam_internal()`, which reaches `__yppwlookup()` when YP passwd lookup is enabled.

`getpwuid_r()` follows the same pattern through `getpwuid_internal()`.

Inside `__yppwlookup()`, all three `yp_match()` paths reject only values larger than the buffer:

- `gen/getpwent.c:602`
- `gen/getpwent.c:626`
- `gen/getpwent.c:645`

Because the guard is `ypcurrentlen > buflen`, a YP value with `ypcurrentlen == buflen` is accepted.

The accepted value is copied into the caller buffer and then NUL-terminated:

```c
bcopy(ypcurrent, buf, ypcurrentlen);
buf[ypcurrentlen] = '\0';
```

When `ypcurrentlen == buflen`, the copy fills the entire buffer and the terminator write targets one byte past the caller-supplied allocation.

## Why This Is A Real Bug

The reentrant APIs explicitly receive a caller-owned buffer and length. `__yppwlookup()` must reserve space for the terminating NUL before copying data that is later parsed as a string.

A malicious YP server can return a passwd map value whose byte length exactly matches the victim buffer length. Under that condition, the overflow occurs before `__ypparse()` can reject malformed content, so parser validation does not mitigate the memory corruption.

## Fix Requirement

Reject YP passwd map values when `ypcurrentlen >= buflen`, not only when `ypcurrentlen > buflen`.

## Patch Rationale

The patch updates all three `yp_match()` result checks in `__yppwlookup()` from:

```c
ypcurrentlen > buflen
```

to:

```c
ypcurrentlen >= buflen
```

This preserves one byte of space for the explicit NUL terminator written at `buf[ypcurrentlen]`.

The change is applied consistently to:

- Direct `+` lookup.
- Netgroup `+@` lookup.
- Named `+user` lookup.

## Residual Risk

None

## Patch

```diff
diff --git a/gen/getpwent.c b/gen/getpwent.c
index d851711..dca5707 100644
--- a/gen/getpwent.c
+++ b/gen/getpwent.c
@@ -599,7 +599,7 @@ __yppwlookup(int lookup, char *name, uid_t uid, struct passwd *pw,
 				r = yp_match(__ypdomain, map,
 				    name, strlen(name),
 				    &ypcurrent, &ypcurrentlen);
-				if (r != 0 || ypcurrentlen > buflen) {
+				if (r != 0 || ypcurrentlen >= buflen) {
 					free(ypcurrent);
 					ypcurrent = NULL;
 					continue;
@@ -623,7 +623,7 @@ pwnam_netgrp:
 						    &ypcurrent, &ypcurrentlen);
 					} else
 						goto pwnam_netgrp;
-					if (r != 0 || ypcurrentlen > buflen) {
+					if (r != 0 || ypcurrentlen >= buflen) {
 						free(ypcurrent);
 						ypcurrent = NULL;
 						/*
@@ -642,7 +642,7 @@ pwnam_netgrp:
 				r = yp_match(__ypdomain, map,
 				    user, strlen(user),
 				    &ypcurrent, &ypcurrentlen);
-				if (r != 0 || ypcurrentlen > buflen) {
+				if (r != 0 || ypcurrentlen >= buflen) {
 					free(ypcurrent);
 					ypcurrent = NULL;
 					continue;
```