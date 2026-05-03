# semaphore wake path dereferences freed semid

## Classification

Denial of service, high severity.

Confidence: certain.

## Affected Locations

`kern/sysv_sem.c:671`

## Summary

`sys_semop()` keeps a `struct semid_ds *semaptr` across `tsleep_nsec()`. If the semaphore set is removed while the caller sleeps, `IPC_RMID` frees that object. A same-index `semget()` recreation can make `sema[semid]` non-`NULL` before the sleeper resumes. The wake path then checks the stale `semaptr->sem_perm.seq`, dereferencing freed kernel memory and potentially panicking the system.

## Provenance

Verified from the provided source, reproducer analysis, and patch.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Attacker can create and remove System V semaphore sets.
- Attacker can issue a blocking `semop()` on a semaphore set they can write.
- Attacker can race `IPC_RMID` and same-index `semget()` recreation before the sleeping `semop()` thread resumes.

## Proof

The vulnerable path is:

1. `sys_semop()` resolves `semaptr = sema[semid]` before sleeping.
2. An unsatisfied operation increments `semzcnt` or `semncnt` and sleeps on `&sema[semid]`.
3. `IPC_RMID` frees `semaptr->sem_base`, returns `semaptr` to `sema_pool`, clears `sema[ix]`, clears undo state, and wakes sleepers.
4. `sys_semget()` can reuse the cleared array index because allocation scans for the first `NULL` `sema[]` slot and stores a new `semid_ds *` there.
5. The sleeper resumes. If the index was recreated, `sema[semid] != NULL`, so the old check proceeds to evaluate `semaptr->sem_perm.seq`.
6. That `semaptr` is the stale pre-sleep pointer to the freed `semid_ds`.

The reproduced impact is a kernel use-after-free reachable by a local user, with denial-of-service potential through kernel panic.

## Why This Is A Real Bug

The original revalidation was not safe after sleep:

```c
if (sema[semid] == NULL ||
    semaptr->sem_perm.seq != IPCID_TO_SEQ(SCARG(uap, semid))) {
```

The first condition only protects the case where the slot is still empty. It does not protect the recreated-slot case. Because `semaptr` was captured before sleeping, `semaptr->sem_perm.seq` can dereference memory already freed by `IPC_RMID`.

The sequence number check is intended to detect stale IDs, but it must be performed against the current `sema[semid]` object, not the pre-sleep pointer.

## Fix Requirement

After waking, validate using only `sema[semid]` as the source of truth. Reload `semaptr` from `sema[semid]` before reading fields from the semaphore descriptor.

## Patch Rationale

The patch changes the post-sleep existence check to assign the current slot value into `semaptr`:

```diff
-		if (sema[semid] == NULL ||
+		if ((semaptr = sema[semid]) == NULL ||
 		    semaptr->sem_perm.seq != IPCID_TO_SEQ(SCARG(uap, semid))) {
```

This ensures the subsequent sequence validation reads from the live object currently installed in `sema[semid]`. If the original semaphore was removed and no replacement exists, the check returns `EIDRM`. If a replacement exists with a different sequence number, the sequence check returns `EIDRM` without touching the freed descriptor.

## Residual Risk

None

## Patch

`028-semaphore-wake-path-dereferences-freed-semid.patch`

```diff
diff --git a/kern/sysv_sem.c b/kern/sysv_sem.c
index f13a53b..6eac699 100644
--- a/kern/sysv_sem.c
+++ b/kern/sysv_sem.c
@@ -675,7 +675,7 @@ sys_semop(struct proc *p, void *v, register_t *retval)
 		/*
 		 * Make sure that the semaphore still exists
 		 */
-		if (sema[semid] == NULL ||
+		if ((semaptr = sema[semid]) == NULL ||
 		    semaptr->sem_perm.seq != IPCID_TO_SEQ(SCARG(uap, semid))) {
 			error = EIDRM;
 			goto done2;
```