# unchecked procfd target indexes peer arrays

## Classification

High severity out-of-bounds write.

## Affected Locations

`sbin/iked/proc.c:674`

## Summary

`proc_dispatch()` accepts `IMSG_CTL_PROCFD`, copies attacker-controlled `struct privsep_fd` fields from `imsg.data`, and passes `pf.pf_procid` and `pf.pf_instance` directly to `proc_accept()`. `proc_accept()` used those values as indexes into `ps->ps_ievs[dst]`, `pp->pp_pipes[dst][n]`, and `ps->ps_ievs[dst][n]` without validating that `dst < PROC_MAX` and `n < ps->ps_instances[dst]`.

A malicious or compromised iked privsep peer able to send imsgs could therefore cause out-of-bounds peer-array access and assignment in the receiving process.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Attacker controls an iked privsep peer process.
- The attacker-controlled peer can send imsgs over an existing privsep channel.
- The peer sends `IMSG_CTL_PROCFD` with crafted `pf_procid` or `pf_instance` values.

## Proof

`proc_dispatch()` handles `IMSG_CTL_PROCFD` by size-checking the payload, copying `struct privsep_fd` from `imsg.data`, and calling:

```c
proc_accept(ps, imsg_get_fd(&imsg), pf.pf_procid, pf.pf_instance);
```

`struct privsep_fd` carries both target indexes from the message payload. Before the patch, `proc_accept()` used those values directly:

```c
if (ps->ps_ievs[dst] == NULL) {
	close(fd);
	return;
}

if (pp->pp_pipes[dst][n] != -1) {
	close(fd);
	return;
} else
	pp->pp_pipes[dst][n] = fd;

iev = &ps->ps_ievs[dst][n];
```

The peer arrays are bounded by `PROC_MAX` and `ps->ps_instances[dst]`. No receiving-side bounds check existed before indexing. Supplying an out-of-range `pf_procid` or `pf_instance` therefore reaches out-of-bounds reads/writes in the receiver.

## Why This Is A Real Bug

The vulnerable indexes are not derived from local trusted state on the receiving path. They are copied from imsg payload data supplied by the sending peer. The first access in `proc_accept()` dereferences `ps->ps_ievs[dst]` before any range validation, and later accesses use both `dst` and `n` to read and write descriptor slots. Because `IMSG_CTL_PROCFD` is part of the generic dispatch path, a compromised lower-privileged privsep peer can target another process, including the privileged parent, through a crafted control message.

## Fix Requirement

Validate both indexes before any array access in `proc_accept()`:

- Reject `dst < 0`.
- Reject `dst >= PROC_MAX`.
- Reject `n >= ps->ps_instances[dst]`.
- Close the received fd on rejection to avoid descriptor leaks.

## Patch Rationale

The patch adds an early guard at the start of `proc_accept()`:

```c
if (dst < 0 || dst >= PROC_MAX || n >= ps->ps_instances[dst]) {
	log_warnx("%s: invalid process descriptor", __func__);
	close(fd);
	return;
}
```

This ensures `ps->ps_instances[dst]`, `ps->ps_ievs[dst]`, `pp->pp_pipes[dst][n]`, and `ps->ps_ievs[dst][n]` are only evaluated after `dst` is known to be within `PROC_MAX` and `n` is known to be within the configured instance count for that process type. Closing the fd preserves existing cleanup behavior for rejected descriptors.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/iked/proc.c b/sbin/iked/proc.c
index ecff708..beab1d5 100644
--- a/sbin/iked/proc.c
+++ b/sbin/iked/proc.c
@@ -276,6 +276,12 @@ proc_accept(struct privsep *ps, int fd, enum privsep_procid dst,
 	struct privsep_pipes	*pp = ps->ps_pp;
 	struct imsgev		*iev;
 
+	if (dst < 0 || dst >= PROC_MAX || n >= ps->ps_instances[dst]) {
+		log_warnx("%s: invalid process descriptor", __func__);
+		close(fd);
+		return;
+	}
+
 	if (ps->ps_ievs[dst] == NULL) {
 #if DEBUG > 1
 		log_debug("%s: %s src %d %d to dst %d %d not connected",
```