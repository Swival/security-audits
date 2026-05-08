# remove query escapes source tree

## Classification

Information disclosure, low severity. Confidence: certain.

## Affected Locations

`usr.bin/rdist/client.c:527`

## Summary

A malicious `rdist` server can send `CC_QUERY` remove-check filenames containing `../` traversal. The client appends the decoded server-controlled name to the local target directory and calls `lstat()`, then replies differently depending on whether the resulting traversed path exists. This exposes an existence oracle for client filesystem paths outside the intended source tree.

## Provenance

Verified from supplied source, reproducer summary, and patch. Originally identified by Swival Security Scanner: https://swival.dev

## Preconditions

The client runs an install operation with `DO_REMOVE` enabled against a malicious server.

## Proof

`senddir()` invokes `rmchk()` when `DO_REMOVE` is set at `usr.bin/rdist/client.c:608`.

Inside `rmchk()`, the client sends `C_CLEAN` and then accepts server-controlled response lines via `remline()` at `usr.bin/rdist/client.c:507`. For `CC_QUERY`, the attacker-controlled filename is decoded into `targ` at `usr.bin/rdist/client.c:520`.

Before the patch, `targ` was appended directly to the local target directory:

```c
(void) snprintf(ptarget,
    sizeof(target) - (ptarget - target),
    "%s%s",
    (ptarget[-1] == '/' ? "" : "/"),
    targ);
```

The resulting path was then passed to `lstat()` at `usr.bin/rdist/client.c:532`.

A malicious server can complete the install handshake with `C_ACK`, then send records such as:

```text
Q../../../../etc/passwd
```

If the traversed path exists, the client sends `CC_NO`; if `lstat()` fails, it sends `CC_YES`. This leaks whether arbitrary traversable local paths exist.

## Why This Is A Real Bug

The queried filename is controlled by the server during remove checking, not by the local filesystem walk. `rmchk()` uses it to construct a local path without rejecting parent-directory components. Because the response differs on `lstat()` success versus failure, the malicious server learns client-side filesystem state outside the source tree. Absolute names are appended under the source prefix, but enough `../` components escape that prefix.

## Fix Requirement

Reject server-supplied remove-query names before `lstat()` if they are absolute or contain any path component equal to `..`.

## Patch Rationale

The patch validates `targ` immediately after decoding and before appending it to `target`. It rejects:

- absolute paths beginning with `/`
- the exact path `..`
- paths beginning with `../`
- paths containing `/../`
- paths ending with `/..`

This blocks traversal components from reaching the `snprintf()` path construction and subsequent `lstat()` oracle.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/rdist/client.c b/usr.bin/rdist/client.c
index ef4a574..8b9999f 100644
--- a/usr.bin/rdist/client.c
+++ b/usr.bin/rdist/client.c
@@ -521,6 +521,14 @@ rmchk(opt_t opts)
 				error("rmchk: cannot decode file");
 				return(-1);
 			}
+			if (targ[0] == '/' || strcmp(targ, "..") == 0 ||
+			    strncmp(targ, "../", 3) == 0 ||
+			    strstr(targ, "/../") != NULL ||
+			    (strlen(targ) >= 3 &&
+			    strcmp(targ + strlen(targ) - 3, "/..") == 0)) {
+				error("rmchk: invalid filename");
+				return(-1);
+			}
 			(void) snprintf(ptarget,
 					sizeof(target) - (ptarget - target),
 					"%s%s",
```