# resolver info messages overflow fixed status array

## Classification

High severity out-of-bounds write.

Confidence: certain.

## Affected Locations

- `usr.sbin/unwindctl/unwindctl.c:56`
- `usr.sbin/unwindctl/unwindctl.c:168`
- `usr.sbin/unwindctl/unwindctl.c:197`
- `usr.sbin/unwindctl/unwindctl.c:259`

## Summary

`unwindctl status` stores resolver status messages in a fixed global array, but accepted an unbounded number of `IMSG_CTL_RESOLVER_INFO` messages from the connected control socket. When connected to an attacker-controlled socket via `-s`, a malicious peer could send more resolver info messages than the array can hold, causing a global out-of-bounds write and subsequent out-of-bounds reads.

The patch bounds the copy by ignoring additional resolver info messages once `info_cnt` reaches `UW_RES_NONE`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was manually reproduced and patched from the supplied affected source and reproducer evidence.

## Preconditions

- The user runs `unwindctl status`.
- The user connects `unwindctl` to an attacker-controlled UNIX control socket using `-s`.
- The malicious socket peer sends more than `UW_RES_NONE` valid-sized `IMSG_CTL_RESOLVER_INFO` messages before `IMSG_CTL_END`.

## Proof

`unwindctl` accepts an attacker-chosen socket path through `-s` and connects to it before processing imsg responses.

For the `STATUS` action, the client sends `IMSG_CTL_STATUS` and dispatches each received message to `show_status_msg`.

The destination storage is fixed-size:

```c
struct ctl_resolver_info info[UW_RES_NONE];
```

`UW_RES_NONE` is the enum terminator after seven resolver types, so the global array has seven elements.

Before the patch, every `IMSG_CTL_RESOLVER_INFO` caused an unconditional copy:

```c
memcpy(&info[info_cnt++], imsg->data, sizeof(info[0]));
```

A malicious peer can send eight valid-sized `IMSG_CTL_RESOLVER_INFO` messages followed by `IMSG_CTL_END`. The eighth message writes to `info[7]`, one element past the seven-element `info` array.

Afterward, `info_cnt` is also used by later display and histogram loops, causing the process to trust the inflated count and read past the same fixed array.

## Why This Is A Real Bug

The write target is computed directly from attacker-influenced message count. There is no pre-patch bounds check between repeated `IMSG_CTL_RESOLVER_INFO` messages and `info[info_cnt++]`.

The attack does not require malformed message sizes in the reproduced scenario; it only requires too many valid resolver info messages from a socket peer selected by the user through `-s`.

The impact is concrete memory corruption of the `unwindctl` process, with likely crash or corrupted output state.

## Fix Requirement

`show_status_msg` must not write past `info[UW_RES_NONE]`.

Additional `IMSG_CTL_RESOLVER_INFO` messages received after `info_cnt` reaches `UW_RES_NONE` must be rejected, ignored, or otherwise handled without incrementing `info_cnt` or copying into the fixed array.

## Patch Rationale

The patch adds a direct capacity check before copying into `info`:

```c
if (info_cnt < UW_RES_NONE)
	memcpy(&info[info_cnt++], imsg->data, sizeof(info[0]));
```

This preserves existing behavior for valid resolver info counts and prevents both the out-of-bounds write and the later out-of-bounds reads caused by an inflated `info_cnt`.

Ignoring excess resolver info messages is sufficient because `UW_RES_NONE` is the fixed maximum number of resolver slots that the rest of the status display code can safely process.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/unwindctl/unwindctl.c b/usr.sbin/unwindctl/unwindctl.c
index 2735c33..f878b2e 100644
--- a/usr.sbin/unwindctl/unwindctl.c
+++ b/usr.sbin/unwindctl/unwindctl.c
@@ -257,7 +257,8 @@ show_status_msg(struct imsg *imsg)
 
 	switch (imsg->hdr.type) {
 	case IMSG_CTL_RESOLVER_INFO:
-		memcpy(&info[info_cnt++], imsg->data, sizeof(info[0]));
+		if (info_cnt < UW_RES_NONE)
+			memcpy(&info[info_cnt++], imsg->data, sizeof(info[0]));
 		break;
 	case IMSG_CTL_END:
 		if (fwd_line[0] != '\0')
```