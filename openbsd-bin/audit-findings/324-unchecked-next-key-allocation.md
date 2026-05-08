# Unchecked NEXT Key Allocation

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.sbin/ypserv/common/yplib_host.c:222`

## Summary

`yp_next_host()` trusts a successful `YPPROC_NEXT` response from the YP server and allocates output buffers using peer-controlled key and value lengths. The key allocation result is not checked before `memcpy()` and NUL termination. A malicious YP server can return an oversized successful key, force `malloc()` to return `NULL`, and crash the consuming YP client process through a NULL pointer write.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

The client queries an attacker-controlled YP server using `yp_next_host()`.

## Proof

`yp_next_host()` sends `YPPROC_NEXT` and decodes the server response into `struct ypresp_key_val yprkv`.

On protocol success:

```c
*outkeylen = yprkv.key.keydat_len;
*outkey = malloc(*outkeylen+1);
memcpy(*outkey, yprkv.key.keydat_val, *outkeylen);
(*outkey)[*outkeylen] = '\0';
```

The server controls `yprkv.key.keydat_len` and `yprkv.key.keydat_val`. If the server returns `YP_TRUE` with an oversized key length, `malloc(*outkeylen + 1)` can fail and return `NULL`. The following `memcpy(*outkey, ...)` and `(*outkey)[*outkeylen] = '\0'` dereference `NULL`, terminating the client process.

The same unchecked pattern exists for the value allocation in `yp_next_host()`, but the unchecked key allocation alone is sufficient to reproduce the denial of service.

## Why This Is A Real Bug

The decoded `ypresp_key_val` contents are attacker-controlled under the stated precondition. The function treats `ypprot_err(yprkv.stat) == 0` as sufficient validation and does not verify allocation success before writing to the allocated buffers. C library `malloc()` is permitted to return `NULL` on allocation failure, and passing `NULL` as the destination to `memcpy()` or indexing it for NUL termination is invalid and crashes the process.

This is an attacker-triggered denial of service against any client process that consumes data through `yp_next_host()` from a malicious YP server.

## Fix Requirement

Check `malloc()` results before copying into the output buffers. On allocation failure, return `YP_YPERR`, free any partially allocated output, clear dangling output pointers, and still release the decoded XDR response with `xdr_free()`.

## Patch Rationale

The patch adds explicit NULL checks after both allocations in `yp_next_host()`.

For key allocation failure, it sets `r = YP_YPERR` and jumps to common cleanup before any write through `*outkey`.

For value allocation failure, it frees the already allocated key buffer, clears `*outkey`, sets `r = YP_YPERR`, and jumps to common cleanup before any write through `*outval`.

The shared `out:` label preserves the existing `xdr_free(xdr_ypresp_key_val, ...)` cleanup path for both success and failure.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ypserv/common/yplib_host.c b/usr.sbin/ypserv/common/yplib_host.c
index 4a42107..bad28ad 100644
--- a/usr.sbin/ypserv/common/yplib_host.c
+++ b/usr.sbin/ypserv/common/yplib_host.c
@@ -219,13 +219,24 @@ yp_next_host(CLIENT *client, char *indomain, char *inmap, char *inkey,
 	if ( !(r = ypprot_err(yprkv.stat)) ) {
 		*outkeylen = yprkv.key.keydat_len;
 		*outkey = malloc(*outkeylen+1);
+		if (*outkey == NULL) {
+			r = YP_YPERR;
+			goto out;
+		}
 		memcpy(*outkey, yprkv.key.keydat_val, *outkeylen);
 		(*outkey)[*outkeylen] = '\0';
 		*outvallen = yprkv.val.valdat_len;
 		*outval = malloc(*outvallen+1);
+		if (*outval == NULL) {
+			free(*outkey);
+			*outkey = NULL;
+			r = YP_YPERR;
+			goto out;
+		}
 		memcpy(*outval, yprkv.val.valdat_val, *outvallen);
 		(*outval)[*outvallen] = '\0';
 	}
+out:
 	xdr_free(xdr_ypresp_key_val, (char *)&yprkv);
 	return r;
 }
```