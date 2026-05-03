# Unprivileged Verauth Clear Ioctl

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

`kern/tty_tty.c:119`

## Summary

`TIOCCLRVERAUTH` on `/dev/tty` clears the verified-auth state for the caller’s controlling-tty session without requiring privilege. Any unprivileged local process that shares the controlling tty session can invalidate that session’s verified-auth state, causing later verification checks to fail until a privileged process restores it.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced from the committed source and patched in `031-unprivileged-verauth-clear-ioctl.patch`.

## Preconditions

- The attacker is a local process.
- The attacker has a controlling tty in the target session.
- The session has verified-auth state set.
- The attacker can issue `TIOCCLRVERAUTH` on `/dev/tty`.

## Proof

`cttyioctl()` first resolves the caller’s controlling tty through `cttyvp(p)`. If no controlling tty exists, it returns `EIO`; otherwise, it handles selected ioctls directly.

`TIOCSETVERAUTH` is privileged:

```c
case TIOCSETVERAUTH:
	if ((error = suser(p)))
		return error;
	secs = *(int *)addr;
	if (secs < 1 || secs > 3600)
		return EINVAL;
	sess = p->p_p->ps_pgrp->pg_session;
	sess->s_verauthuid = p->p_ucred->cr_ruid;
	sess->s_verauthppid = p->p_p->ps_ppid;
	timeout_add_sec(&sess->s_verauthto, secs);
	return 0;
```

`TIOCCLRVERAUTH` had no matching privilege check:

```c
case TIOCCLRVERAUTH:
	sess = p->p_p->ps_pgrp->pg_session;
	timeout_del(&sess->s_verauthto);
	zapverauth(sess);
	return 0;
```

`zapverauth(sess)` clears the session verification fields. A later `TIOCCHKVERAUTH` compares those fields against the caller’s real uid and parent pid and returns `EPERM` after the unprivileged clear invalidates the state.

Therefore, an unprivileged process sharing the controlling tty session can clear session verauth state and deny subsequent verification.

## Why This Is A Real Bug

The verified-auth state is session-scoped and security-sensitive. Setting that state already requires `suser(p)`, demonstrating that mutation of this state is intended to be privileged.

Clearing the same state is also a mutation with security impact. Without a privilege check, an ordinary process in the same controlling-tty session can disrupt later verification for legitimate users or processes. The ioctl returns success after deleting the timeout and clearing the state, so the denial of service is direct and reliable under the stated preconditions.

## Fix Requirement

Require `suser(p)` before `TIOCCLRVERAUTH` mutates session verified-auth state.

## Patch Rationale

The patch adds the same privilege gate used by `TIOCSETVERAUTH` before `TIOCCLRVERAUTH` deletes the timeout or calls `zapverauth(sess)`.

This preserves the existing behavior for privileged callers while preventing unprivileged local processes from clearing session verauth state.

## Residual Risk

None

## Patch

```diff
diff --git a/kern/tty_tty.c b/kern/tty_tty.c
index 8198eaf..398c3b7 100644
--- a/kern/tty_tty.c
+++ b/kern/tty_tty.c
@@ -120,6 +120,8 @@ cttyioctl(dev_t dev, u_long cmd, caddr_t addr, int flag, struct proc *p)
 		timeout_add_sec(&sess->s_verauthto, secs);
 		return 0;
 	case TIOCCLRVERAUTH:
+		if ((error = suser(p)))
+			return error;
 		sess = p->p_p->ps_pgrp->pg_session;
 		timeout_del(&sess->s_verauthto);
 		zapverauth(sess);
```