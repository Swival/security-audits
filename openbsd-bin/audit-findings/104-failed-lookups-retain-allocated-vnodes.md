# Failed Lookups Retain Allocated Vnodes

## Classification

Denial of service, medium severity, confidence certain.

## Affected Locations

`lib/libfuse/fuse_ops.c:448`

## Summary

`ifuse_ops_lookup()` allocates and inserts a vnode for a cache miss before validating the backing filesystem object with `getattr`. If `getattr` fails, lookup replies with an error but leaves the newly inserted vnode referenced in the FUSE daemon’s vnode structures. Repeated failed lookups of unique names can grow daemon memory without bound.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- A FUSE filesystem is mounted.
- The mounted filesystem’s `getattr` callback returns errors for missing unique names.
- A local process can access the FUSE mount and trigger lookups for attacker-chosen names.

## Proof

On lookup miss, `ifuse_ops_lookup()` calls `alloc_vn(f, name, -1, parent)` and then immediately calls `set_vn(f, vn)`, inserting the vnode into daemon state.

It then builds `realname` and calls:

```c
err = update_attr(f, &entry.attr, realname, vn->ino);
```

`update_attr()` calls the filesystem’s `getattr` callback and returns its error. If `getattr` fails, control reaches `out:` and the original code only does:

```c
fuse_reply_err(req, -err);
```

It does not call `unref_vn(f, vn)`, which is the cleanup primitive that removes entries from the vnode trees and frees the vnode. Therefore each failed lookup of a unique missing name can leave a retained vnode in `f->vnode_tree`.

A local actor can repeatedly stat or otherwise resolve distinct nonexistent paths under the mount. Each unique failed lookup allocates another vnode and associated tree/dict state, while returning no usable FUSE entry to the kernel.

## Why This Is A Real Bug

The allocation and insertion happen before successful lookup completion, but the error path lacks matching cleanup. Because the attacker controls the looked-up filename and can make each name unique, the retained vnode set can grow with the number of failed lookups. There is no source-visible eviction or bounding mechanism on this path, so daemon memory exhaustion is a realistic denial-of-service outcome.

## Fix Requirement

If `ifuse_ops_lookup()` allocates and inserts a new vnode for a lookup, and the lookup later fails before replying with `fuse_reply_entry()`, it must remove/unreference that newly allocated vnode before replying with the error.

## Patch Rationale

The patch adds a `newvn` flag to distinguish vnodes allocated during the current lookup from pre-existing vnodes.

- `newvn` is initialized to `0`.
- After successful `alloc_vn()` and `set_vn()`, `newvn` is set to `1`.
- On the error path, `unref_vn(f, vn)` is called only when `newvn` is true.
- Existing vnodes are not removed on lookup failure, preserving existing cache/reference semantics.
- Successful lookups still reply with `fuse_reply_entry()` unchanged.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/libfuse/fuse_ops.c b/lib/libfuse/fuse_ops.c
index 9527191..bfe8163 100644
--- a/lib/libfuse/fuse_ops.c
+++ b/lib/libfuse/fuse_ops.c
@@ -444,7 +444,7 @@ ifuse_ops_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
 	struct fuse_entry_param entry;
 	struct fuse_vnode *vn;
 	char *realname;
-	int err;
+	int err, newvn = 0;
 
 	vn = get_vn_by_name_and_parent(f, name, parent);
 	if (vn == NULL) {
@@ -454,6 +454,7 @@ ifuse_ops_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
 			goto out;
 		}
 		set_vn(f, vn); /*XXX*/
+		newvn = 1;
 	} else if (vn->ino != FUSE_ROOT_INO)
 		ref_vn(vn);
 
@@ -471,8 +472,11 @@ ifuse_ops_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
 out:
 	if (!err)
 		fuse_reply_entry(req, &entry);
-	else
+	else {
+		if (newvn)
+			unref_vn(f, vn);
 		fuse_reply_err(req, -err);
+	}
 }
 
 static void
```