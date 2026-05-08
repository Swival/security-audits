# Peer-Supplied Instance Indexes Descriptor Table Out Of Bounds

## Classification

Out-of-bounds read/write leading to daemon crash/DoS.

Severity: medium.

Confidence: certain.

## Affected Locations

`usr.sbin/snmpd/proc.c:257`

## Summary

`proc_dispatch()` accepts `IMSG_CTL_PROCFD` from an established privsep imsg peer, copies a peer-controlled `struct privsep_fd`, and passes `pf.pf_procid` and `pf.pf_instance` directly to `proc_accept()`.

`proc_accept()` used those values to index descriptor and event tables without proving that the destination process id and instance number were within the allocated bounds. A malicious privsep peer can therefore send an out-of-range instance index and cause out-of-bounds access in the daemon.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the provided source and patch evidence.

## Preconditions

- Attacker controls an established privsep imsg peer.
- The peer can send `IMSG_CTL_PROCFD`.
- The peer can choose `struct privsep_fd.pf_procid` and `struct privsep_fd.pf_instance`.

## Proof

`proc_dispatch()` handles `IMSG_CTL_PROCFD` by checking only the payload size, then copying attacker-controlled data:

```c
IMSG_SIZE_CHECK(&imsg, &pf);
memcpy(&pf, imsg.data, sizeof(pf));
proc_accept(ps, imsg_get_fd(&imsg), pf.pf_procid, pf.pf_instance);
```

At `usr.sbin/snmpd/proc.c:636`, `pf.pf_procid` and `pf.pf_instance` reach `proc_accept()` without range validation.

Before the patch, `proc_accept()` only checked whether `ps->ps_ievs[dst] == NULL`. It did not validate:

- `dst < PROC_MAX`
- `n < ps->ps_instances[dst]`

The peer-controlled index was then used here:

```c
if (pp->pp_pipes[dst][n] != -1) {
```

and later here:

```c
iev = &ps->ps_ievs[dst][n];
```

Those arrays are allocated in `proc_setup()` for only `ps->ps_instances[dst]` entries. A malicious lower-privileged privsep peer such as `snmpe` can send `pf_procid = PROC_SNMPE` with a huge `pf_instance`, causing out-of-bounds heap access in the parent and a practical daemon crash/DoS.

`IMSG_SIZE_CHECK` does not prevent this because it validates only the message payload length, not the semantic range of the copied fields.

## Why This Is A Real Bug

The vulnerable indexes are attacker-controlled across an established privsep imsg channel.

The allocation bounds are explicit: `ps->ps_ievs[id]` and `pp->pp_pipes[dst]` are allocated for `ps->ps_instances[id]` or `ps->ps_instances[dst]` elements. Accessing element `n` is valid only when `n < ps->ps_instances[dst]`.

Because `proc_accept()` performed no such check, an out-of-range `pf_instance` reached heap-backed descriptor and event arrays. This is a concrete memory safety violation and can crash the daemon.

## Fix Requirement

Reject invalid process ids and instance indexes before any descriptor or event table access:

- Reject `pf_procid` values outside `[0, PROC_MAX)`.
- Reject `pf_instance` values greater than or equal to `ps->ps_instances[pf_procid]`.
- Close the received descriptor when rejecting the message to avoid descriptor leaks.

## Patch Rationale

The patch adds a guard at the start of `proc_accept()`:

```c
if ((unsigned int)dst >= PROC_MAX || n >= ps->ps_instances[dst]) {
	close(fd);
	return;
}
```

This is the correct choke point because all `IMSG_CTL_PROCFD` descriptor acceptance flows through `proc_accept()`.

The guard prevents both unsafe array dimensions from being used:

- `dst` is validated before indexing `ps->ps_ievs[dst]`, `ps->ps_instances[dst]`, or `pp->pp_pipes[dst]`.
- `n` is validated before indexing `pp->pp_pipes[dst][n]` or `ps->ps_ievs[dst][n]`.

Closing `fd` preserves existing error-path behavior and prevents a malformed peer message from leaking the passed descriptor.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/snmpd/proc.c b/usr.sbin/snmpd/proc.c
index bbf7335..be671de 100644
--- a/usr.sbin/snmpd/proc.c
+++ b/usr.sbin/snmpd/proc.c
@@ -248,6 +248,11 @@ proc_accept(struct privsep *ps, int fd, enum privsep_procid dst,
 	struct privsep_pipes	*pp = ps->ps_pp;
 	struct imsgev		*iev;
 
+	if ((unsigned int)dst >= PROC_MAX || n >= ps->ps_instances[dst]) {
+		close(fd);
+		return;
+	}
+
 	if (ps->ps_ievs[dst] == NULL) {
 #if DEBUG > 1
 		log_debug("%s: %s src %d %d to dst %d %d not connected",
```