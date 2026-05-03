# pledge-open fchflags drops unowned vnode reference

## Classification

Denial of service; high severity; local unprivileged kernel reference/lock corruption.

## Affected Locations

`kern/vfs_syscalls.c:2264`

## Summary

`sys_fchflags()` obtains a vnode-backed file descriptor with `getvnode()`. `getvnode()` returns only an FREF'ed `struct file`; it does not acquire or lock a vnode reference. When the descriptor is marked `UF_PLEDGEOPEN`, `sys_fchflags()` calls `vput(vp)` and returns `EPERM`. That releases and unlocks a vnode reference owned by the file object, corrupting vnode reference/lock state and enabling local denial of service.

## Provenance

Found by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A local process has a pledge-open vnode file descriptor.

## Proof

`sys___pledge_open()` passes `UNVEIL_PLEDGEOPEN` into `doopenat()` at `kern/vfs_syscalls.c:1072`.

`doopenat()` marks the returned descriptor with `UF_PLEDGEOPEN` when `pledgeopen && vp->v_type != VCHR` at `kern/vfs_syscalls.c:1171`.

`sys_fchflags()` calls `getvnode()`, assigns `vp = fp->f_data`, and on the `UF_PLEDGEOPEN` branch calls `vput(vp)` before returning `EPERM` at `kern/vfs_syscalls.c:2316`.

`getvnode()` documents that it returns only an FREF'ed `struct file` at `kern/vfs_syscalls.c:3282`. The underlying `fd_getfile()` increments only `fp->f_count`, not `vp->v_usecount`, at `kern/kern_descrip.c:227`.

`vput()` decrements `v_usecount` and unlocks/inactivates the vnode at `kern/vfs_subr.c:756`. Because `sys_fchflags()` neither `vref()`s nor locks `vp` before the pledge-open branch, this path drops an unowned vnode reference and attempts to unlock an unlocked vnode.

## Why This Is A Real Bug

The normal `sys_fchflags()` path correctly calls `vref(vp)`, releases the file with `FRELE(fp, p)`, and transfers the owned vnode reference into `dovchflags()`, which later consumes it with `vput(vp)`.

The `UF_PLEDGEOPEN` path returns before that `vref(vp)` occurs, so it owns only the file reference returned by `getvnode()`. Calling `vput(vp)` on that path mismatches ownership. The reachable result is vnode reference count corruption and lock misuse from an unprivileged local process that can pass a pledge-open descriptor to `fchflags()`.

## Fix Requirement

On the `UF_PLEDGEOPEN` denial path, release the file reference acquired by `getvnode()` and do not release or unlock the vnode.

## Patch Rationale

Replacing `vput(vp)` with `FRELE(fp, p)` matches the ownership model:

- `getvnode()` gives `sys_fchflags()` one file reference.
- The pledge-open denial path has not acquired a vnode reference.
- `FRELE(fp, p)` releases exactly the acquired file reference.
- The vnode reference held by the file object remains intact.

## Residual Risk

None

## Patch

```diff
diff --git a/kern/vfs_syscalls.c b/kern/vfs_syscalls.c
index 137c743..085f8f0 100644
--- a/kern/vfs_syscalls.c
+++ b/kern/vfs_syscalls.c
@@ -2317,7 +2317,7 @@ sys_fchflags(struct proc *p, void *v, register_t *retval)
 		return (error);
 	vp = fp->f_data;
 	if (p->p_fd->fd_ofileflags[SCARG(uap, fd)] & UF_PLEDGEOPEN) {
-		vput(vp);
+		FRELE(fp, p);
 		return (EPERM);
 	}
 	vref(vp);
```