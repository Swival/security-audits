# Unbounded Exports Allocation

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.bin/showmount/showmount.c:320`

## Summary

`showmount` decodes attacker-controlled `RPCMNT_EXPORT` replies using `xdr_exports`. The decoder trusts remote XDR boolean continuation markers for both the export list and each export's group list. Before the patch, each true marker caused a heap allocation with no count limit, allowing a malicious mount daemon to force unbounded local memory growth until allocation or RPC decoding failed.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The user runs `showmount -e` or otherwise requests exports.
- The queried host is attacker-controlled or its mount daemon response is attacker-controlled.
- The attacker returns an `RPCMNT_EXPORT` reply with repeated true continuation markers.

## Proof

`main` calls `clnt_call` for `RPCMNT_EXPORT` with `xdr_exports` as the response decoder.

In the vulnerable decoder:

- The export loop at `usr.bin/showmount/showmount.c:318` uses a remote XDR boolean as the list continuation condition.
- Each true export marker allocates `struct exportslist` at `usr.bin/showmount/showmount.c:319`.
- The group loop at `usr.bin/showmount/showmount.c:328` also uses a remote XDR boolean as the continuation condition.
- Each true group marker allocates `struct grouplist` at `usr.bin/showmount/showmount.c:329`.
- Only individual string lengths are bounded by `RPCMNT_PATHLEN` at `usr.bin/showmount/showmount.c:324` and `RPCMNT_NAMELEN` at `usr.bin/showmount/showmount.c:333`.
- There was no export-count or group-count limit before allocation.

A malicious RPC mount daemon can return a syntactically valid `RPCMNT_EXPORT` stream containing repeated true list markers and bounded strings, including empty strings. `showmount` continues allocating nodes until `malloc` fails, `xdr_exports` returns failure, `clnt_call` reports non-success, and `main` exits at `usr.bin/showmount/showmount.c:177`.

## Why This Is A Real Bug

The allocation behavior is controlled by the remote RPC peer, not by local input size or a trusted file. Per-string caps do not bound aggregate allocation because the attacker controls the number of list elements. This gives an attacker-controlled mount daemon a direct way to exhaust client memory and terminate `showmount`, producing a local denial of service.

## Fix Requirement

Impose explicit maximum counts while decoding the `RPCMNT_EXPORT` export list and group lists. The decoder must reject responses that exceed those limits before performing additional allocations.

## Patch Rationale

The patch adds:

- `MAXEXPORTS` set to `1024`.
- `MAXGROUPS` set to `1024`.
- An export counter checked before each `struct exportslist` allocation.
- A group counter checked before each `struct grouplist` allocation.

This converts remote-controlled unbounded allocation into bounded allocation. Oversized malicious replies now cause `xdr_exports` to fail before memory growth can continue indefinitely.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/showmount/showmount.c b/usr.bin/showmount/showmount.c
index c264f68..3ae93dc 100644
--- a/usr.bin/showmount/showmount.c
+++ b/usr.bin/showmount/showmount.c
@@ -55,6 +55,9 @@
 #define	DODUMP		0x1
 #define	DOEXPORTS	0x2
 
+#define	MAXEXPORTS	1024
+#define	MAXGROUPS	1024
+
 struct mountlist {
 	struct mountlist *ml_left;
 	struct mountlist *ml_right;
@@ -310,12 +313,15 @@ xdr_exports(XDR *xdrsp, struct exportslist **exp)
 	struct exportslist *ep;
 	struct grouplist *gp;
 	int bool, grpbool;
+	int exports_count = 0, groups_count = 0;
 	char *strp;
 
 	*exp = NULL;
 	if (!xdr_bool(xdrsp, &bool))
 		return (0);
 	while (bool) {
+		if (exports_count++ >= MAXEXPORTS)
+			return (0);
 		ep = malloc(sizeof(struct exportslist));
 		if (ep == NULL)
 			return (0);
@@ -326,6 +332,8 @@ xdr_exports(XDR *xdrsp, struct exportslist **exp)
 		if (!xdr_bool(xdrsp, &grpbool))
 			return (0);
 		while (grpbool) {
+			if (groups_count++ >= MAXGROUPS)
+				return (0);
 			gp = malloc(sizeof(struct grouplist));
 			if (gp == NULL)
 				return (0);
```