# peer process indexes fd arrays without bounds checks

## Classification

High severity out-of-bounds write.

## Affected Locations

`usr.sbin/relayd/proc.c:658`

## Summary

`proc_dispatch()` accepts peer-supplied `IMSG_CTL_PROCFD` messages, copies `pf_procid` and `pf_instance` from the message body, and passes them directly to `proc_accept()`. `proc_accept()` used those values as indexes into `ps->ps_ievs[dst]`, `pp->pp_pipes[dst][n]`, and `ps->ps_ievs[dst][n]` without validating that `dst` is a valid process id or that `n` is a valid instance index. A compromised relayd privsep peer could therefore trigger out-of-bounds descriptor/event array access in the receiving relayd process.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

An attacker controls a connected relayd privsep peer process and can send an `IMSG_CTL_PROCFD` message over its existing imsg socket.

## Proof

`proc_dispatch()` handles `IMSG_CTL_PROCFD` by checking only that the message body has the size of `struct privsep_fd`, then copying peer-controlled fields:

```c
IMSG_SIZE_CHECK(&imsg, &pf);
memcpy(&pf, imsg.data, sizeof(pf));
proc_accept(ps, imsg_get_fd(&imsg), pf.pf_procid, pf.pf_instance);
```

Before the patch, `proc_accept()` immediately dereferenced peer-controlled indexes:

```c
if (ps->ps_ievs[dst] == NULL) {
	...
}

if (pp->pp_pipes[dst][n] != -1) {
	...
} else
	pp->pp_pipes[dst][n] = fd;

iev = &ps->ps_ievs[dst][n];
```

The arrays are allocated only for valid process ids and configured instance counts:

- `ps->ps_ievs[id]` is allocated with `ps->ps_instances[id]` elements in `proc_setup()`.
- `pp->pp_pipes[dst]` is allocated with `ps->ps_instances[dst]` elements in `proc_setup()`.

Thus an out-of-range `pf_procid` or `pf_instance` exceeds the allocated object bounds.

## Why This Is A Real Bug

The vulnerable values are supplied by a peer process over an imsg channel, not derived from trusted local state. The receiver validates message size but not semantic bounds. `proc_accept()` then performs both reads and writes through unchecked indexes, including `pp->pp_pipes[dst][n] = fd`. A compromised child can therefore corrupt memory in another relayd process, including a privileged parent or another sandboxed process, causing at least denial of service and creating a plausible privsep boundary escape primitive.

## Fix Requirement

Reject `IMSG_CTL_PROCFD` destinations where:

- `pf_procid < 0`
- `pf_procid >= PROC_MAX`
- `pf_instance >= ps->ps_instances[pf_procid]`

The rejection must happen before any access to `ps->ps_ievs[dst]`, `pp->pp_pipes[dst]`, or `ps->ps_instances[dst]` through an unvalidated `dst`.

## Patch Rationale

The patch adds an early bounds check at the start of `proc_accept()`:

```c
if (dst < 0 || dst >= PROC_MAX || n >= ps->ps_instances[dst]) {
	log_warnx("%s: invalid descriptor destination", __func__);
	close(fd);
	return;
}
```

This ensures `dst` is within the valid `PROC_MAX` range before it is used to index `ps_instances`, `ps_ievs`, or `pp_pipes`. It also ensures `n` is within the configured instance count for that destination process before the descriptor and event arrays are accessed. Invalid peer-supplied descriptors are closed to avoid fd leaks.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/relayd/proc.c b/usr.sbin/relayd/proc.c
index 361f05a..f0f1d54 100644
--- a/usr.sbin/relayd/proc.c
+++ b/usr.sbin/relayd/proc.c
@@ -249,6 +249,12 @@ proc_accept(struct privsep *ps, int fd, enum privsep_procid dst,
 	struct privsep_pipes	*pp = ps->ps_pp;
 	struct imsgev		*iev;
 
+	if (dst < 0 || dst >= PROC_MAX || n >= ps->ps_instances[dst]) {
+		log_warnx("%s: invalid descriptor destination", __func__);
+		close(fd);
+		return;
+	}
+
 	if (ps->ps_ievs[dst] == NULL) {
 #if DEBUG > 1
 		log_debug("%s: %s src %d %d to dst %d %d not connected",
```