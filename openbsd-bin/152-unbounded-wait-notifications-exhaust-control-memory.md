# Unbounded Wait Notifications Exhaust Control Memory

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.sbin/vmd/control.c:470`

## Summary

A lower-privileged local client that can connect to the `vmd` control socket can repeatedly submit `WAIT` or `TERMINATE` requests with `VMOP_WAIT`. Each accepted request allocates and queues a `struct ctl_notify` without a per-client bound. Repetition can exhaust control-process memory, and allocation failure calls `fatal()`, terminating the control process.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Attacker can connect to the `vmd` control socket.
- Attacker can issue repeated `IMSG_VMDOP_WAIT_VM_REQUEST` or `IMSG_VMDOP_TERMINATE_VM_REQUEST` messages.
- A persistent trigger exists when waiting on a running VM the client is authorized to control.

## Proof

`control_dispatch_imsg()` permits non-root clients to send `IMSG_VMDOP_WAIT_VM_REQUEST` and `IMSG_VMDOP_TERMINATE_VM_REQUEST` before the root-only gate.

For each wait request, the function allocates a notification and appends it to the global queue:

```c
notify = calloc(1, sizeof(struct ctl_notify));
if (notify == NULL)
	fatal("%s: calloc", __func__);
notify->ctl_vmid = vid.vid_id;
notify->ctl_fd = fd;
TAILQ_INSERT_TAIL(&ctl_notify_q, notify, entry);
```

There is no duplicate check, per-client cap, or global cap before insertion. Entries remain pending until a matching VM termination event. Client disconnect does not fully bound accumulation because `control_close()` removes only the first matching wait entry and then breaks.

On memory exhaustion, `calloc()` returns `NULL`, `fatal("%s: calloc", __func__)` is called, and `fatal()` exits the process with status 1. This makes repeated wait registration an attacker-triggered local denial of service.

## Why This Is A Real Bug

The queued notification is attacker-controlled state in the control process. A client can cause one persistent allocation per accepted wait request, while cleanup depends on future VM termination or incomplete close cleanup. Because allocation failure is handled with `fatal()` rather than a recoverable error, memory pressure escalates from resource consumption to control-process termination.

The root-only gate does not prevent the issue because the relevant wait-capable message types are explicitly allowed before the uid check.

## Fix Requirement

The control process must reject excessive or duplicate pending waits before allocating another `ctl_notify`. Allocation failure must be returned to the client as an error instead of terminating the process.

## Patch Rationale

The patch enforces one pending wait notification per control connection by scanning `ctl_notify_q` for an existing entry with the same client fd. If one exists, the request fails with `EBUSY` and no additional memory is allocated.

The patch also replaces `fatal()` on `calloc()` failure with a recoverable `ENOMEM` failure path. This prevents low-memory conditions from terminating the control process.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/vmd/control.c b/usr.sbin/vmd/control.c
index bf58b43..8f9f940 100644
--- a/usr.sbin/vmd/control.c
+++ b/usr.sbin/vmd/control.c
@@ -466,9 +466,17 @@ control_dispatch_imsg(int fd, short event, void *arg)
 
 			if (wait || vid.vid_flags & VMOP_WAIT) {
 				vid.vid_flags |= VMOP_WAIT;
+				TAILQ_FOREACH(notify, &ctl_notify_q, entry) {
+					if (notify->ctl_fd == fd) {
+						ret = EBUSY;
+						goto fail;
+					}
+				}
 				notify = calloc(1, sizeof(struct ctl_notify));
-				if (notify == NULL)
-					fatal("%s: calloc", __func__);
+				if (notify == NULL) {
+					ret = ENOMEM;
+					goto fail;
+				}
 				notify->ctl_vmid = vid.vid_id;
 				notify->ctl_fd = fd;
 				TAILQ_INSERT_TAIL(&ctl_notify_q, notify, entry);
```