# unchecked MATCH value allocation

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`usr.sbin/ypserv/common/yplib_host.c:150`

## Summary

`yp_match_host()` trusts the value length returned by a YP server and allocates `*outvallen + 1` bytes for the returned value. The allocation result is used immediately without a NULL check. An attacker-controlled YP server can return an oversized successful `YPPROC_MATCH` value that causes `malloc()` to fail, after which `memcpy()` writes through a NULL destination and terminates the consuming client process.

## Provenance

Identified by Swival Security Scanner: https://swival.dev

## Preconditions

A client binds to an attacker-controlled YP server and calls `yp_match_host()`.

## Proof

`yp_match_host()` sends `YPPROC_MATCH` with `clnt_call()` and decodes the reply into `yprv`.

When `ypprot_err(yprv.stat)` reports success, the function:

- assigns `yprv.val.valdat_len` to `*outvallen`
- calls `malloc(*outvallen + 1)`
- does not check whether `malloc()` returned NULL
- immediately passes `*outval` to `memcpy()`
- writes the trailing NUL byte through `(*outval)[*outvallen]`

For an oversized successful response from a malicious YP server, `malloc()` can return NULL. The following `memcpy(*outval, yprv.val.valdat_val, *outvallen)` then dereferences NULL and crashes the client process.

The reproducer confirmed that a crafted server response can drive the success path and terminate the consuming client process via the unchecked allocation destination.

## Why This Is A Real Bug

The server response controls `yprv.val.valdat_len`, and the client code uses that value to size an allocation. Allocation failure is a normal, expected failure mode for attacker-influenced large lengths. Because the allocation result is not checked before use, the process can be reliably crashed instead of returning an error.

This is reachable by any client that has bound to a malicious or attacker-controlled YP server and calls `yp_match_host()`, making the impact a concrete client-side denial of service.

## Fix Requirement

Check the result of `malloc()` before copying into the output buffer. If allocation fails, reset the output length and return an allocation/resource error instead of calling `memcpy()` or writing the NUL terminator.

## Patch Rationale

The patch preserves the existing success behavior when allocation succeeds and changes only the allocation-failure path.

On `malloc()` failure, it:

- leaves `*outval` as NULL
- resets `*outvallen` to `0`
- returns `YPERR_RESRC`
- skips `memcpy()` and the trailing NUL write
- still frees decoded XDR state through the existing `xdr_free()` call

This converts the attacker-triggered crash into a normal error return.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ypserv/common/yplib_host.c b/usr.sbin/ypserv/common/yplib_host.c
index 4a42107..6cac9a7 100644
--- a/usr.sbin/ypserv/common/yplib_host.c
+++ b/usr.sbin/ypserv/common/yplib_host.c
@@ -147,8 +147,13 @@ yp_match_host(CLIENT *client, char *indomain, char *inmap, const char *inkey,
 	if ( !(r = ypprot_err(yprv.stat)) ) {
 		*outvallen = yprv.val.valdat_len;
 		*outval = malloc(*outvallen+1);
-		memcpy(*outval, yprv.val.valdat_val, *outvallen);
-		(*outval)[*outvallen] = '\0';
+		if (*outval == NULL) {
+			*outvallen = 0;
+			r = YPERR_RESRC;
+		} else {
+			memcpy(*outval, yprv.val.valdat_val, *outvallen);
+			(*outval)[*outvallen] = '\0';
+		}
 	}
 	xdr_free(xdr_ypresp_val, (char *)&yprv);
 	return r;
```