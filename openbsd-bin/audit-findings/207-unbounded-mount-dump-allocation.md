# Unbounded Mount Dump Allocation

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.bin/showmount/showmount.c:241`

## Summary

`showmount` decodes `RPCMNT_DUMP` replies from the queried mount daemon with no maximum entry count or aggregate allocation budget. An attacker-controlled mount daemon can return an arbitrarily long sequence of true list markers, causing `showmount` to allocate one `struct mountlist` per decoded entry until client memory is exhausted.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

The user runs `showmount` against an attacker-controlled or malicious mount daemon and requests mount dump data, either implicitly or with dump-related options such as `-a` or `-d`.

## Proof

`main` calls `clnt_call` for `RPCMNT_DUMP` with `xdr_mntdump` as the reply decoder.

In `xdr_mntdump`:

- `xdr_bool` reads the initial attacker-supplied list marker.
- The decoder loops while that marker is true.
- Each loop iteration allocates `sizeof(struct mountlist)`.
- `xdr_string` limits only the individual host and path string lengths.
- The next attacker-supplied boolean is read after allocation and insertion/drop logic.
- No entry-count or aggregate allocation limit exists before the patch.

A malicious RPC mount daemon can send valid, unique host/path pairs with continued true list markers. Unique entries are retained in the tree instead of dropped as duplicates, so memory consumption grows until `malloc` fails and the RPC decode returns failure.

A local harness using valid XDR mount entries and a capped allocator confirmed that decoding continues allocating once per true marker and fails only when the artificial allocation cap is reached.

## Why This Is A Real Bug

The input controls the number of decoded list elements, and each element causes heap allocation. Existing bounds apply only to per-string sizes, not to the number of entries. Therefore, a remote mount daemon can force unbounded client-side memory growth from a single dump response, producing a reliable denial of service for the invoking `showmount` process.

## Fix Requirement

Enforce a finite maximum number of decoded mount dump entries, or otherwise enforce an aggregate allocation budget, before allocating additional `struct mountlist` objects.

## Patch Rationale

The patch adds `MNTDUMP_MAX_ENTRIES` and increments a local counter before each allocation in `xdr_mntdump`. If the decoded entry count exceeds the configured limit, decoding fails immediately instead of continuing to allocate attacker-controlled entries.

This directly bounds the allocation loop while preserving existing behavior for normal replies within the limit.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/showmount/showmount.c b/usr.bin/showmount/showmount.c
index c264f68..3d15bdb 100644
--- a/usr.bin/showmount/showmount.c
+++ b/usr.bin/showmount/showmount.c
@@ -55,6 +55,8 @@
 #define	DODUMP		0x1
 #define	DOEXPORTS	0x2
 
+#define	MNTDUMP_MAX_ENTRIES	1024
+
 struct mountlist {
 	struct mountlist *ml_left;
 	struct mountlist *ml_right;
@@ -231,13 +233,15 @@ int
 xdr_mntdump(XDR *xdrsp, struct mountlist **mlp)
 {
 	struct mountlist *mp, **otp = NULL, *tp;
-	int bool, val, val2;
+	int bool, count = 0, val, val2;
 	char *strp;
 
 	*mlp = NULL;
 	if (!xdr_bool(xdrsp, &bool))
 		return (0);
 	while (bool) {
+		if (++count > MNTDUMP_MAX_ENTRIES)
+			return (0);
 		mp = malloc(sizeof(struct mountlist));
 		if (mp == NULL)
 			return (0);
```