# Recursive Notice Responses Exhaust Stack

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`usr.bin/rdist/common.c:542`

## Summary

`response()` recursively called itself for every `C_NOTEMSG` response from the remote peer. An attacker-controlled peer could send an unbounded stream of notice records without an ACK or error response, causing one additional stack frame per notice until the `rdist` process exhausted its stack and terminated.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

The `rdist` process reads protocol responses from an attacker-controlled peer.

## Proof

`response()` reads a remote line with `remline(s = resp, sizeof(resp), 0)` and dispatches on the first byte. For `C_NOTEMSG`, the original code logged the notice and executed `return(response());`.

`C_NOTEMSG` is protocol byte `'\3'`, so a malicious peer controlling the remote descriptor can repeatedly send records such as:

```text
\003notice\n
\003notice\n
\003notice\n
...
```

Because each notice causes another recursive `response()` call and there is no notice count limit, the call stack grows until stack exhaustion terminates the process. The read timeout does not prevent this because the peer can continuously send notice lines and avoid blocking.

## Why This Is A Real Bug

The vulnerable path is reachable from normal client response handling: the remote peer is connected through `rem_r`, and `response()` consumes data from that descriptor. Notice messages are valid protocol records, but the implementation handled them with unbounded recursion instead of iteration. A peer does not need to send malformed input or trigger exceptional behavior; it only needs to send many valid `C_NOTEMSG` records without a terminating ACK, log, or error response.

The impact is attacker-triggered denial of service against the local `rdist` process.

## Fix Requirement

Replace recursive `C_NOTEMSG` handling with iterative processing, and bound the number of consecutive notices accepted before returning an error.

## Patch Rationale

The patch converts `response()` into a loop. Normal terminal responses still return immediately:

- `C_ACK` returns success.
- `C_LOGMSG` preserves the previous log-message behavior.
- `C_ERRMSG` and unknown responses return error.
- `C_FERRMSG` reports the fatal error and calls `finish()`.

For `C_NOTEMSG`, the patched code logs the notice and continues the loop instead of recursively calling `response()`. It also tracks consecutive notices and returns `-1` after more than `BUFSIZ` notices, preventing both stack exhaustion and unbounded notice processing.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/rdist/common.c b/usr.bin/rdist/common.c
index 8243dfe..721feaf 100644
--- a/usr.bin/rdist/common.c
+++ b/usr.bin/rdist/common.c
@@ -522,44 +522,48 @@ response(void)
 {
 	static u_char resp[BUFSIZ];
 	u_char *s;
-	int n;
+	int n, notices = 0;
 
 	debugmsg(DM_CALL, "response() start\n");
 
-	n = remline(s = resp, sizeof(resp), 0);
+	for (;;) {
+		n = remline(s = resp, sizeof(resp), 0);
 
-	n--;
-	switch (*s++) {
+		n--;
+		switch (*s++) {
         case C_ACK:
-		debugmsg(DM_PROTO, "received ACK\n");
-		return(0);
-	case C_LOGMSG:
-		if (n > 0) {
-			message(MT_CHANGE, "%s", s);
-			return(1);
+			debugmsg(DM_PROTO, "received ACK\n");
+			return(0);
+		case C_LOGMSG:
+			if (n > 0) {
+				message(MT_CHANGE, "%s", s);
+				return(1);
+			}
+			debugmsg(DM_PROTO, "received EMPTY logmsg\n");
+			return(0);
+		case C_NOTEMSG:
+			if (++notices > BUFSIZ)
+				return(-1);
+			if (s)
+				message(MT_NOTICE, "%s", s);
+			continue;
+
+		default:
+			s--;
+			n++;
+			/* fall into... */
+
+		case C_ERRMSG:	/* Normal error message */
+			if (s)
+				message(MT_NERROR, "%s", s);
+			return(-1);
+
+		case C_FERRMSG:	/* Fatal error message */
+			if (s)
+				message(MT_FERROR, "%s", s);
+			finish();
+			return(-1);
 		}
-		debugmsg(DM_PROTO, "received EMPTY logmsg\n");
-		return(0);
-	case C_NOTEMSG:
-		if (s)
-			message(MT_NOTICE, "%s", s);
-		return(response());
-
-	default:
-		s--;
-		n++;
-		/* fall into... */
-
-	case C_ERRMSG:	/* Normal error message */
-		if (s)
-			message(MT_NERROR, "%s", s);
-		return(-1);
-
-	case C_FERRMSG:	/* Fatal error message */
-		if (s)
-			message(MT_FERROR, "%s", s);
-		finish();
-		return(-1);
 	}
 	/*NOTREACHED*/
 }
```