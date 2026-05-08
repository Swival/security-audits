# Unbounded Exports XDR Recursion

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.sbin/amd/rpcx/mount_xdr.c:171`

## Summary

`xdr_exports()` decodes an attacker-controlled mount RPC exports list through recursive `xdr_pointer()` calls without enforcing a depth or element limit. A malicious mount RPC peer can return a deeply nested non-null exports chain that exhausts the automounter stack and terminates the affected decode path.

## Provenance

Verified and reproduced from the provided finding and reproducer evidence.

Scanner provenance: https://swival.dev

Confidence: certain.

## Preconditions

- The automounter decodes exports from an attacker-controlled mount RPC response.
- The malicious peer can supply a crafted exports XDR list.
- The list contains many consecutive non-null `ex_next` pointers before a final terminator.

## Proof

The vulnerable decode path is:

- `xdr_exports()` calls `xdr_pointer(..., xdr_exportnode)`.
- `xdr_exportnode()` decodes `ex_dir`.
- `xdr_exportnode()` decodes `ex_groups`.
- `xdr_exportnode()` then decodes `ex_next` by calling `xdr_exports()` again.

Each non-null exports node adds another recursive `xdr_exports()` / `xdr_exportnode()` stack frame. The original implementation has no maximum depth, no element count, and no early rejection of excessive lists.

The reproducer confirmed this behavior with a local XDR harness using the same recursive decoder shape. Shallow crafted input decoded successfully, while deeply nested input crashed from stack exhaustion before semantic processing. With a constrained 64 KB stack, the crash occurred around a few hundred nodes; with the default stack, it occurred at tens of thousands of nodes using only hundreds of KB of XDR input.

## Why This Is A Real Bug

This is a real denial-of-service bug because decoding occurs before any application-level validation and the recursion depth is fully controlled by the RPC peer’s serialized exports list. The crash does not require a large payload, valid export semantics, authentication bypass beyond reaching the mount RPC response path, or unusual process behavior.

The practical trigger path is an automounter mount operation that requests a daemon’s export list. Normal `amd` `host_ops` mount attempts may run in a forked subprocess, so the common victim can be the mount subprocess rather than always the long-lived foreground daemon. This still gives the malicious peer a reliable attacker-controlled path to terminate the automount operation and force repeated mount failure. Any foreground or direct caller of the same decoder would terminate in the same way.

## Fix Requirement

The decoder must reject excessive exports list nesting before stack exhaustion can occur.

Acceptable fixes include:

- Enforcing a maximum exports list depth during decode.
- Rewriting exports list decoding iteratively with an element limit.

## Patch Rationale

The patch adds `MAX_EXPORTS` and tracks decode recursion depth in `xdr_exports()`:

```c
#define MAX_EXPORTS 1024
```

During `XDR_DECODE`, `xdr_exports()` increments `exports_depth` before calling `xdr_pointer()`. If the depth is already at or above `MAX_EXPORTS`, it decrements the counter and returns `FALSE`, rejecting the malformed response before unbounded recursion continues.

The guard is scoped to decode operations only, preserving existing encode/free behavior. The counter is decremented after `xdr_pointer()` returns, so normal recursive unwinding restores the previous depth.

A limit of 1024 permits large legitimate exports lists while bounding stack consumption from malicious input.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/amd/rpcx/mount_xdr.c b/usr.sbin/amd/rpcx/mount_xdr.c
index bc4cf4e..3fc4800 100644
--- a/usr.sbin/amd/rpcx/mount_xdr.c
+++ b/usr.sbin/amd/rpcx/mount_xdr.c
@@ -42,6 +42,8 @@
 
 #include <nfs/rpcv2.h>
 
+#define MAX_EXPORTS 1024
+
 int
 xdr_fhstatus(XDR *xdrsp, fhstatus *objp)
 {
@@ -150,10 +152,18 @@ xdr_groupnode(XDR *xdrs, groupnode *objp)
 bool_t
 xdr_exports(XDR *xdrs, exports *objp)
 {
-	if (!xdr_pointer(xdrs, (char **)objp, sizeof(struct exportnode), xdr_exportnode)) {
+	static int exports_depth;
+	bool_t rv;
+
+	if (xdrs->x_op == XDR_DECODE && exports_depth++ >= MAX_EXPORTS) {
+		exports_depth--;
 		return (FALSE);
 	}
-	return (TRUE);
+	rv = xdr_pointer(xdrs, (char **)objp, sizeof(struct exportnode),
+	    xdr_exportnode);
+	if (xdrs->x_op == XDR_DECODE)
+		exports_depth--;
+	return (rv);
 }
 
 bool_t
```