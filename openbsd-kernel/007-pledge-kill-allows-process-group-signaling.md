# pledge kill allows process-group signaling

## Classification

security_control_failure; severity high; confidence certain.

## Affected Locations

`kern/kern_pledge.c:1607`

## Summary

`pledge_kill()` incorrectly allowed `kill(0, sig)` for pledged processes that lacked the `proc` promise. In `kill(2)` semantics, PID zero targets the caller's process group, not only the caller. This let a local pledged process with only `stdio` signal other same-process-group processes despite the pledge comment and policy allowing only self-signaling without `proc`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A local process has called `pledge()` without the `proc` promise, for example `pledge("stdio", NULL)`, and shares a process group with another signalable process.

## Proof

`sys_kill()` calls `pledge_kill(cp, pid)` before normal kill routing. For a pledged process without `PLEDGE_PROC`, the vulnerable implementation returned success when `pid == 0`:

```c
if (pid == 0 || pid == p->p_p->ps_pid)
	return 0;
```

After that success path, normal `kill(2)` handling interprets `pid == 0` as process-group signaling via `killpg1(cp, signum, 0, 0)`. `killpg1()` then iterates members of the caller's process group and calls `prsignal()` for each target permitted by `cansignal()`. Same-credential targets satisfy those checks.

A practical trigger is:

```c
pledge("stdio", NULL);
kill(0, SIGTERM);
```

when another same-credential process is in the same process group.

## Why This Is A Real Bug

The pledge table comment for `SYS_kill` states: "Can kill self with `stdio`. Killing another pid requires `proc`." PID zero is not self-only; it is process-group addressing. Therefore the old allow condition accepted an input that can signal other processes while the process lacks `PLEDGE_PROC`. This is a deterministic policy bypass, not a documentation-only mismatch.

## Fix Requirement

For a pledged process without `PLEDGE_PROC`, allow only PID equal to the caller's own process ID. Reject PID zero and all other non-self kill targets through the existing pledge failure path.

## Patch Rationale

The patch removes the `pid == 0` exception from `pledge_kill()`. This aligns the authorization check with the documented pledge policy: `stdio` permits self-signaling only, while process-group or other process signaling requires `proc`.

## Residual Risk

None

## Patch

```diff
diff --git a/kern/kern_pledge.c b/kern/kern_pledge.c
index 2186172..e68bef2 100644
--- a/kern/kern_pledge.c
+++ b/kern/kern_pledge.c
@@ -1613,7 +1613,7 @@ pledge_kill(struct proc *p, pid_t pid)
 		return 0;
 	if (p->p_pledge & PLEDGE_PROC)
 		return 0;
-	if (pid == 0 || pid == p->p_p->ps_pid)
+	if (pid == p->p_p->ps_pid)
 		return 0;
 	return pledge_fail(p, EPERM, PLEDGE_PROC);
 }
```