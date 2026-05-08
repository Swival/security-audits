# Truncated PAP Header Reads Past Packet

## Classification

Out-of-bounds read, medium severity.

## Affected Locations

`usr.sbin/npppd/npppd/pap.c:164`

## Summary

`pap_input()` reads the PAP `code`, `id`, and `length` fields before verifying that the supplied PAP payload contains the four-byte PAP header. A remote PPP peer can send a PAP frame with a payload shorter than four bytes after PAP is negotiated, causing `GETCHAR`/`GETSHORT` to read past the packet buffer.

## Provenance

Verified from supplied source, reproducer analysis, and patch.

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- PAP is started.
- A remote PPP peer can send a truncated PAP protocol frame.
- The PAP payload length passed to `pap_input()` is less than four bytes.

## Proof

`pap_input()` accepts attacker-controlled `pktp` and `lpktp`.

Before the patch, it immediately executed:

```c
pktp1 = pktp;

GETCHAR(code, pktp1);
GETCHAR(id, pktp1);
GETSHORT(length, pktp1);
```

These macros dereference and advance the packet pointer without validating remaining length.

The first PAP packet-length validation occurred later:

```c
if (lpktp < length) {
	pap_log(_this, LOG_ERR, "%s: Received broken packet.",
	    __func__);
	return -1;
}
```

That check is reached only after four header bytes have already been read.

The reproducer confirmed reachability:

- `ppp_lcp_up()` calls `pap_start()` at `usr.sbin/npppd/npppd/ppp.c:483`.
- `ppp_recv_packet()` only checks the whole PPP frame is at least four bytes at `usr.sbin/npppd/npppd/ppp.c:750`.
- PAP payload length is dispatched directly to `pap_input()` at `usr.sbin/npppd/npppd/ppp.c:896`.
- A PAP payload shorter than four bytes therefore reaches the unchecked header reads.

## Why This Is A Real Bug

The PAP header is four bytes: one byte `code`, one byte `id`, and two bytes `length`. The function reads all four bytes unconditionally. If `lpktp < 4`, the reads access memory beyond the supplied PAP payload.

The later `lpktp < length` check does not protect these reads because `length` itself is obtained from the unchecked header.

## Fix Requirement

Reject PAP payloads shorter than four bytes before reading `code`, `id`, or `length`.

## Patch Rationale

The patch adds an early `lpktp < 4` check immediately after the PAP state validation and before assigning `pktp1` or invoking `GETCHAR`/`GETSHORT`.

This preserves existing error handling semantics by logging `"Received broken packet."` and returning `-1`, matching the later malformed-packet path.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/npppd/npppd/pap.c b/usr.sbin/npppd/npppd/pap.c
index f234f23..b56fb42 100644
--- a/usr.sbin/npppd/npppd/pap.c
+++ b/usr.sbin/npppd/npppd/pap.c
@@ -160,6 +160,11 @@ pap_input(pap *_this, u_char *pktp, int lpktp)
 		    "not started.");
 		return -1;
 	}
+	if (lpktp < 4) {
+		pap_log(_this, LOG_ERR, "%s: Received broken packet.",
+		    __func__);
+		return -1;
+	}
 	pktp1 = pktp;
 
 	GETCHAR(code, pktp1);
```