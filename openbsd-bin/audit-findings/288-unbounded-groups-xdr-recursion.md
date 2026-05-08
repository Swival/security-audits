# unbounded groups XDR recursion

## Classification

denial of service, medium severity

## Affected Locations

`usr.sbin/amd/rpcx/mount_xdr.c:147`

## Summary

`xdr_exportnode` decodes attacker-supplied mount export groups through `xdr_groups`. `xdr_groups` uses `xdr_pointer` with `xdr_groupnode` as the element decoder, and `xdr_groupnode` recursively decodes `gr_next` by calling `xdr_groups` again. The original code has no recursion-depth or element-count limit, so a malicious mount RPC response can force unbounded recursive decoding and exhaust the automounter stack.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The automounter decodes exports from an attacker-controlled mount RPC response.
- The malicious peer returns an export list containing a deeply nested, non-null groups chain.

## Proof

The vulnerable decode path is:

- `xdr_exportnode` decodes `ex_groups` via `xdr_groups`.
- `xdr_groups` dispatches group decoding through `xdr_pointer`.
- `xdr_pointer` invokes `xdr_groupnode` for each non-null group node.
- `xdr_groupnode` decodes `gr_next` by recursively calling `xdr_groups`.

A crafted accepted mount RPC reply can contain one export with a zero-length `ex_dir`, followed by many non-null group nodes with zero-length `gr_name`, and finally a null `gr_next`.

Runtime reproduction confirmed that this path decoded 50,000 groups successfully, then segfaulted from stack exhaustion at 100,000 groups with an approximately 800 KB reply. This is practical over the TCP path attempted first by `host_fmount`.

## Why This Is A Real Bug

The crash occurs during XDR reply decoding, before higher-level mount-export handling can reject or ignore the group list. The input is controlled by the mount RPC peer, and the recursive decode chain is source-visible and unbounded in the original implementation. A remote malicious peer can therefore terminate the automounter process by returning a deeply nested groups list.

## Fix Requirement

The decoder must impose a hard bound on groups recursion depth or decode the list iteratively with a maximum node cap. The bound must apply while decoding untrusted XDR input and must cause decoding to fail cleanly once exceeded.

## Patch Rationale

The patch adds `XDR_GROUPS_MAX_DEPTH` with a limit of 1024 and tracks active groups decode depth during `XDR_DECODE`.

When `xdr_groups` is entered during decode, it increments `xdr_groups_depth` and rejects the input if the configured maximum depth has already been reached. The counter is decremented on both failure and normal return, preserving balanced state across recursive calls.

The guard is decode-only, so existing encode/free behavior is not changed. Valid group lists below the cap continue to decode normally, while maliciously deep lists fail before stack exhaustion.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/amd/rpcx/mount_xdr.c b/usr.sbin/amd/rpcx/mount_xdr.c
index bc4cf4e..c42e123 100644
--- a/usr.sbin/amd/rpcx/mount_xdr.c
+++ b/usr.sbin/amd/rpcx/mount_xdr.c
@@ -42,6 +42,10 @@
 
 #include <nfs/rpcv2.h>
 
+#define XDR_GROUPS_MAX_DEPTH	1024
+
+static int xdr_groups_depth;
+
 int
 xdr_fhstatus(XDR *xdrsp, fhstatus *objp)
 {
@@ -129,10 +133,18 @@ xdr_mountbody(XDR *xdrs, mountbody *objp)
 bool_t
 xdr_groups(XDR *xdrs, groups *objp)
 {
-	if (!xdr_pointer(xdrs, (char **)objp, sizeof(struct groupnode), xdr_groupnode)) {
+	bool_t rv;
+
+	if (xdrs->x_op == XDR_DECODE &&
+	    xdr_groups_depth++ >= XDR_GROUPS_MAX_DEPTH) {
+		xdr_groups_depth--;
 		return (FALSE);
 	}
-	return (TRUE);
+	rv = xdr_pointer(xdrs, (char **)objp, sizeof(struct groupnode),
+	    xdr_groupnode);
+	if (xdrs->x_op == XDR_DECODE)
+		xdr_groups_depth--;
+	return (rv);
 }
 
 bool_t
```