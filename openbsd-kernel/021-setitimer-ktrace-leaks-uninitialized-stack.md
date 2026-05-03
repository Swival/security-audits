# setitimer ktrace leaks uninitialized stack

## Classification

Information disclosure, medium severity.

## Affected Locations

`kern/kern_time.c:661`

## Summary

`sys_setitimer()` can record uninitialized kernel stack bytes into a user-readable ktrace file when `KTR_STRUCT` tracing is enabled and the caller requests only the old timer value. The vulnerable KTRACE block traces `aitv` even when no new timer was supplied and `aitv` was never initialized.

## Provenance

Verified from the supplied source, reproduced behavior summary, and patch.

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A lower-privileged local process can enable `KTR_STRUCT` tracing on itself.
- The process calls `setitimer()` with `itv == NULL`.
- The process supplies `oitv != NULL`.
- The `copyout(&olditv, ...)` path succeeds.

## Proof

In `sys_setitimer()`, two stack objects are declared:

```c
struct itimerval aitv, olditv;
```

When `SCARG(uap, itv) == NULL`, the `copyin()` block is skipped, so `aitv` is not initialized.

When `SCARG(uap, oitv) != NULL`, `olditv` is zeroed and selected as the output buffer:

```c
memset(&olditv, 0, sizeof(olditv));
olditvp = &olditv;
```

`setitimer(which, newitvp, olditvp)` is then called with `newitvp == NULL` and `olditvp == &olditv`, so `setitimer()` fills `olditv`.

After successful copyout, the KTRACE block records the wrong object:

```c
if (error == 0 && KTRPOINT(p, KTR_STRUCT))
	ktritimerval(p, &aitv);
```

`ktritimerval()` records `sizeof(struct itimerval)` bytes from the supplied kernel buffer into the trace stream. On this path, that buffer is uninitialized stack storage.

## Why This Is A Real Bug

The path is reachable by an unprivileged process tracing itself under normal ktrace permission checks. The syscall succeeds with `itv == NULL` and `oitv != NULL`, and the kernel intentionally writes KTRACE struct records for successful output parameters. Because the traced pointer is `&aitv` instead of `&olditv`, the trace file receives raw bytes from an uninitialized kernel stack slot rather than the initialized timer value returned to userspace.

## Fix Requirement

Trace only initialized data. For the `oitv` output path, the KTRACE record must use `olditv`, because that is the object populated by `setitimer()` and copied out to the caller.

## Patch Rationale

The patch changes the post-`copyout()` KTRACE record from `aitv` to `olditv`:

```diff
-			ktritimerval(p, &aitv);
+			ktritimerval(p, &olditv);
```

This preserves existing tracing behavior while making the trace record match the initialized output value. It also avoids tracing `aitv` on paths where no input timer was supplied.

## Residual Risk

None

## Patch

```diff
diff --git a/kern/kern_time.c b/kern/kern_time.c
index cfca2fa..b12566e 100644
--- a/kern/kern_time.c
+++ b/kern/kern_time.c
@@ -665,7 +665,7 @@ sys_setitimer(struct proc *p, void *v, register_t *retval)
 		error = copyout(&olditv, SCARG(uap, oitv), sizeof(olditv));
 #ifdef KTRACE
 		if (error == 0 && KTRPOINT(p, KTR_STRUCT))
-			ktritimerval(p, &aitv);
+			ktritimerval(p, &olditv);
 #endif
 		return error;
 	}
```