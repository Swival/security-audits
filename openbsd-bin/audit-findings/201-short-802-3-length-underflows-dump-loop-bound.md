# Short 802.3 Length Underflows Dump Loop Bound

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.sbin/mopd/common/rc.c:43`

## Summary

`mopDumpRC()` subtracts the 802.3 header adjustment from an attacker-controlled frame length before validating that the length is large enough. For `TRANS_8023`, a length below 8 underflows when assigned to `u_short moplen`, producing a large dump length. CCP or CRA packets then enter the dump loop and read far beyond the short packet while printing, which can crash the dumping process or consume excessive CPU/output.

## Provenance

This finding was verified from the supplied source, reproducer summary, and patch.

Scanner provenance: [Swival Security Scanner](https://swival.dev)

Confidence: certain.

## Preconditions

- `mopd` or `moptrace` receives attacker-supplied 802.3 RC frames from a remote MOP peer on the local network.
- The packet is dumped, such as through `mopProcessRC()` with `DebugFlag >= DEBUG_INFO` or through `moptrace`.
- The frame is classified as `TRANS_8023`.
- The 802.3 RC length is below 8.
- The RC code is `MOP_K_CODE_CCP` or `MOP_K_CODE_CRA`.

## Proof

The reproduced path is:

- `mopProcess()` classifies frames with length `< 1600` as `TRANS_8023`.
- `mopGetHeader()` sets the RC payload index to 22.
- `mopProcessRC()` calls `mopDumpRC()` when debug dumping is enabled; `moptrace` calls `mopDumpRC()` unconditionally.
- In `usr.sbin/mopd/common/rc.c:45`, `moplen = len - 8` is computed for `TRANS_8023`.
- If `len = 1`, the subtraction produces `-7`, which wraps to `65529` in `u_short moplen`.
- For `MOP_K_CODE_CCP` and `MOP_K_CODE_CRA`, the `moplen > 2` check passes.
- The dump loops at `usr.sbin/mopd/common/rc.c:237` and `usr.sbin/mopd/common/rc.c:267` read approximately 65KB via `mopGetChar(pkt, &idx)` from beyond the short captured frame.

## Why This Is A Real Bug

The bug is reachable from attacker-controlled local network input under the stated dumping precondition. The code treats a short 802.3 frame length as a large unsigned payload length, then uses that derived length to drive packet reads and formatted output. The resulting out-of-bounds reads can terminate the daemon or tracing process, and the oversized dump loop can also cause resource exhaustion.

## Fix Requirement

Reject 802.3 RC frames whose length is below 8 before subtracting the 802.3 adjustment and before any dump loop uses the derived payload length.

## Patch Rationale

The patch adds a guard in the `TRANS_8023` case immediately after setting the 802.3 payload index and before `moplen = len - 8`:

```c
if (len < 8)
	return;
```

This prevents unsigned underflow at the source. Valid 802.3 RC frames with `len >= 8` retain the existing behavior, while malformed short frames are not dumped.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/mopd/common/rc.c b/usr.sbin/mopd/common/rc.c
index 3ee7f23..060279b 100644
--- a/usr.sbin/mopd/common/rc.c
+++ b/usr.sbin/mopd/common/rc.c
@@ -42,6 +42,8 @@ mopDumpRC(FILE *fd, u_char *pkt, int trans)
 	switch (trans) {
 	case TRANS_8023:
 		idx = 22;
+		if (len < 8)
+			return;
 		moplen = len - 8;
 		break;
 	default:
```