# guest RTC rate zero triggers negative shift

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`usr.sbin/vmd/mc146818.c:213`

## Summary

A malicious guest can write RTC register A with a zero rate nibble, then enable periodic interrupts through RTC register B. When `vmd` reschedules the emulated RTC periodic timer, it computes a shift count from the guest-controlled rate nibble. A zero nibble produces `0 - 1`, causing a negative shift count and undefined behavior in the VM process.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Guest can perform emulated RTC I/O port writes.

## Proof

Guest RTC I/O exits are routed to `vcpu_exit_mc146818` from `usr.sbin/vmd/x86_vm.c:380`.

In `vcpu_exit_mc146818`, a guest write to `IO_RTC` selects the emulated RTC register index. A subsequent write to `IO_RTC + 1` dispatches writes to `MC_REGA` through `rtc_update_rega` and writes to `MC_REGB` through `rtc_update_regb`.

`rtc_update_regb` stores the guest-controlled register B value and sends `MC146818_RESCHEDULE_PER` whenever `MC_REGB_PIE` is set.

The pipe callback handles `MC146818_RESCHEDULE_PER` by calling `rtc_reschedule_per`.

Before the patch, `rtc_reschedule_per` computed:

```c
rate = 32768 >> ((rtc.regs[MC_REGA] & MC_RATE_MASK) - 1);
```

If the guest sets `MC_REGA & 0xf` to `0` and enables `MC_REGB_PIE`, the expression becomes:

```c
32768 >> (0 - 1)
```

A minimal runtime check of the same expression under UBSan reports:

```text
runtime error: shift exponent -1 is negative
```

## Why This Is A Real Bug

The shift exponent is derived from guest-controlled RTC register state. C does not define behavior for a negative shift count. Therefore a malicious guest can trigger undefined behavior inside the `vmd` VM process through ordinary emulated RTC port writes.

Because the affected process is responsible for VM execution, this is a practical guest-triggered denial-of-service risk.

## Fix Requirement

Reject or clamp a zero RTC register A rate nibble before using it as part of the shift count.

## Patch Rationale

The patch extracts the guest-controlled rate nibble into `period`, checks whether it is zero, and returns before performing the shift.

This preserves the existing behavior for valid nonzero rate values while eliminating the only path where `(period - 1)` can become negative.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/vmd/mc146818.c b/usr.sbin/vmd/mc146818.c
index 6951329..6686397 100644
--- a/usr.sbin/vmd/mc146818.c
+++ b/usr.sbin/vmd/mc146818.c
@@ -209,9 +209,13 @@ rtc_reschedule_per(void)
 {
 	uint16_t rate;
 	uint64_t us;
+	uint8_t period;
 
 	if (rtc.regs[MC_REGB] & MC_REGB_PIE) {
-		rate = 32768 >> ((rtc.regs[MC_REGA] & MC_RATE_MASK) - 1);
+		period = rtc.regs[MC_REGA] & MC_RATE_MASK;
+		if (period == 0)
+			return;
+		rate = 32768 >> (period - 1);
 		us = (1.0 / rate) * 1000000;
 		rtc.per_tv.tv_usec = us;
 		if (evtimer_pending(&rtc.per, NULL))
```