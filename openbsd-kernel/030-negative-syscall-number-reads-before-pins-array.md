# Negative Syscall Number Reads Before Pins Array

## Classification

High severity out-of-bounds read.

Confidence: certain.

## Affected Locations

`sys/syscall_mi.h:82`

## Summary

`pin_check()` accepts a signed `register_t code` and indexes `pin->pn_pins[code]` after checking only `code >= pin->pn_npins`. A negative syscall number bypasses that upper-bound check and reads before the pins array.

The diagnostic `uprintf()` path repeats the same missing lower-bound check, allowing the negative index to be reached again while formatting `pinoff`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced from source review of `mi_syscall()` and `pin_check()`.

## Preconditions

- Process has pinsyscalls enabled.
- Process can invoke a negative syscall code.
- The syscall program counter is inside a populated pinsyscall region.

## Proof

`mi_syscall()` passes the syscall number directly to `pin_check(p, code)` before dispatch.

In `pin_check()`, once `pin` is selected from `ps_pin` or `ps_libcpin`, the original validation was:

```c
if (code >= pin->pn_npins || pin->pn_pins[code] == 0)
	error = ENOSYS;
```

Because `code` is signed, a negative value is not rejected by `code >= pin->pn_npins`. Evaluation then proceeds to `pin->pn_pins[code]`, which reads memory before the allocated pins array.

The error path had the same issue:

```c
(pin && code < pin->pn_npins) ? pin->pn_pins[code] : -1
```

For negative `code`, `code < pin->pn_npins` is true, so `uprintf()` can read and print a 32-bit word from before the pins array as `pinoff`.

Reachability is source-grounded: pins arrays are populated from executable or libc pinsyscall setup in `kern/exec_elf.c:861` and `uvm/uvm_mmap.c:658`, and affected syscall entry paths can pass attacker-controlled syscall numbers into `mi_syscall()`.

## Why This Is A Real Bug

The array index is derived from a signed syscall number without validating the lower bound. Negative values pass the existing upper-bound-only guard and are used directly as an array subscript.

Impact includes:

- Kernel out-of-bounds read before `pn_pins`.
- Local information disclosure through the `uprintf()` diagnostic path.
- Possible kernel fault if the computed pre-array address is invalid.

Some ports, such as amd64 and arm64, reject `code <= 0` before `mi_syscall()`, but the reproduced i386-style path demonstrates the bug in the shared MI pinsyscall validation.

## Fix Requirement

Reject `code < 0` before any `pin->pn_pins[code]` indexing.

The same lower-bound check must be applied to diagnostic paths that conditionally index `pin->pn_pins`.

## Patch Rationale

The patch adds a signed lower-bound check to the primary pinsyscall validation:

```c
if (code < 0 || code >= pin->pn_npins || pin->pn_pins[code] == 0)
```

This prevents negative syscall numbers from reaching any normal `pn_pins` lookup.

The patch also hardens the diagnostic expression:

```c
(pin && code >= 0 && code < pin->pn_npins) ? pin->pn_pins[code] : -1
```

This prevents the error-reporting path from performing the same out-of-bounds read after rejecting the syscall.

## Residual Risk

None

## Patch

```diff
diff --git a/sys/syscall_mi.h b/sys/syscall_mi.h
index e152f14..7213af9 100644
--- a/sys/syscall_mi.h
+++ b/sys/syscall_mi.h
@@ -86,7 +86,7 @@ pin_check(struct proc *p, register_t code)
 		goto die;
 	}
 	if (pin) {
-		if (code >= pin->pn_npins || pin->pn_pins[code] == 0)
+		if (code < 0 || code >= pin->pn_npins || pin->pn_pins[code] == 0)
 			error = ENOSYS;
 		else if (pin->pn_pins[code] + pin->pn_start == addr)
 			; /* correct location */
@@ -108,7 +108,7 @@ die:
 	uprintf("%s[%d]: pinsyscalls addr %lx code %ld, pinoff 0x%x "
 	    "(pin%s %d %lx-%lx %lx) (libcpin%s %d %lx-%lx %lx) error %d\n",
 	    p->p_p->ps_comm, p->p_p->ps_pid, addr, code,
-	    (pin && code < pin->pn_npins) ? pin->pn_pins[code] : -1,
+	    (pin && code >= 0 && code < pin->pn_npins) ? pin->pn_pins[code] : -1,
 	    pin == ppin ? "(Y)" : "", ppin->pn_npins,
 	    ppin->pn_start, ppin->pn_end, ppin->pn_end - ppin->pn_start,
 	    pin == plibcpin ? "(Y)" : "", plibcpin->pn_npins,
```