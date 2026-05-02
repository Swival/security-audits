# UINT_MAX string length desynchronizes XDR decoding

## Classification

High severity request smuggling / XDR stream desynchronization.

Confidence: certain.

## Affected Locations

`rpc/xdr.c:658`

Primary vulnerable logic is in `xdr_string()` around the decoded length check and subsequent `nodesize = size + 1` calculation.

## Summary

`xdr_string()` accepts a decoded string length of `UINT_MAX` when called with `maxsize == UINT_MAX`, including through `xdr_wrapstring()`. The later `nodesize = size + 1` calculation wraps to zero, causing the decode path to return success without consuming the claimed string bytes. Subsequent XDR fields are then decoded from attacker-controlled bytes that should have belonged to the rejected or impossible string body.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the verified report titled `UINT_MAX string length desynchronizes XDR decoding`.

## Preconditions

A caller decodes untrusted XDR strings using either:

- `xdr_wrapstring()`, which passes `LASTUNSIGNED` as `maxsize`
- `xdr_string()` with `maxsize == UINT_MAX`

The XDR input is controlled by a malicious RPC/XDR peer.

## Proof

During decode:

- `xdr_wrapstring()` calls `xdr_string(xdrs, cpp, LASTUNSIGNED)`.
- `xdr_u_int()` reads the peer-controlled 32-bit string length into `size`.
- A length of `0xffffffff` passes the existing `size > maxsize` check when `maxsize == LASTUNSIGNED`.
- `nodesize = size + 1` wraps from `UINT_MAX + 1` to zero.
- The decode branch treats `nodesize == 0` as complete and returns `TRUE` before calling `xdr_opaque()` / `XDR_GETBYTES()`.
- Only the 4-byte length is consumed; the claimed string bytes remain in the stream.

For a composite decoder equivalent to:

```c
xdr_wrapstring(&s);
xdr_u_int(&n);
```

The byte sequence:

```text
ff ff ff ff 00 00 00 2a
```

causes the string decode to succeed and sets `n = 42` from bytes that a conforming decoder would reject or treat as part of the string body.

## Why This Is A Real Bug

The XDR stream cursor becomes desynchronized from the logical data model. A malformed string with impossible length is accepted, and subsequent fields are parsed from attacker-controlled bytes at the wrong boundary.

This creates a request-smuggling primitive when the forged subsequent fields influence authorization, routing, operation selection, or other security-relevant RPC behavior.

## Fix Requirement

Reject decoded string lengths that would overflow the `size + 1` allocation size calculation.

For this codebase, rejecting `size == LASTUNSIGNED` is sufficient because `LASTUNSIGNED` is `((u_int)0-1)`, i.e. `UINT_MAX`.

## Patch Rationale

The patch changes the length validation in `xdr_string()` from:

```c
if (size > maxsize) {
```

to:

```c
if (size > maxsize || size == LASTUNSIGNED) {
```

This preserves the existing maximum-size policy while explicitly rejecting the only `u_int` value that causes `nodesize = size + 1` to wrap to zero.

As a result:

- `UINT_MAX` strings are no longer accepted.
- `nodesize` cannot wrap to zero after validation.
- Decode cannot return success before consuming the string body.
- Subsequent XDR fields remain aligned with the intended stream boundaries.

## Residual Risk

None

## Patch

```diff
diff --git a/rpc/xdr.c b/rpc/xdr.c
index e362446..ad29460 100644
--- a/rpc/xdr.c
+++ b/rpc/xdr.c
@@ -633,7 +633,7 @@ xdr_string(XDR *xdrs, char **cpp, u_int maxsize)
 	if (! xdr_u_int(xdrs, &size)) {
 		return (FALSE);
 	}
-	if (size > maxsize) {
+	if (size > maxsize || size == LASTUNSIGNED) {
 		return (FALSE);
 	}
 	nodesize = size + 1;
```