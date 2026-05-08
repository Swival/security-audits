# guest PIT period can become zero-timeout host event loop

## Classification

denial of service, high severity, certain confidence

## Affected Locations

`usr.sbin/vmd/i8253.c:382`

Relevant reproduced code paths:

`usr.sbin/vmd/i8253.c:291`

`usr.sbin/vmd/i8253.c:306`

`usr.sbin/vmd/i8253.c:351`

`usr.sbin/vmd/i8253.c:373`

`usr.sbin/vmd/i8253.c:377`

## Summary

A malicious guest can program the emulated i8253 PIT with a very small periodic counter value. The host-side timer interval is computed in microseconds using integer division from nanoseconds. For counter value `1`, the computed timeout becomes `0` microseconds. In periodic modes, `i8253_fire()` re-adds the same zero-timeout event after every callback, causing the `vmd` event loop to process immediately due timers continuously and consume host CPU.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was manually reproduced and patched from the provided source and reproducer evidence.

## Preconditions

- A guest can perform PIT port I/O exits.
- The guest can program a PIT channel into a periodic mode.
- The guest can write a tiny counter value, specifically counter value `1`.

## Proof

`vcpu_exit_i8253()` accepts guest `OUT` operations to PIT counter ports. After the second byte of a 16-bit counter write, it stores the guest-controlled value in `i8253_channel[sel].start` and sends a reset request:

- `usr.sbin/vmd/i8253.c:291`
- `usr.sbin/vmd/i8253.c:306`

`i8253_reset()` converts the PIT count to a `struct timeval` timeout:

```c
tv.tv_usec = (i8253_channel[chn].start * NS_PER_TICK) / 1000;
evtimer_add(&i8253_channel[chn].timer, &tv);
```

For `start == 1`, `start * NS_PER_TICK` is less than `1000` nanoseconds, so integer division by `1000` produces `0` microseconds.

`i8253_fire()` then makes the condition self-sustaining for periodic modes:

```c
if (ctr->mode != TIMER_INTTC) {
	timerclear(&tv);
	tv.tv_usec = (ctr->start * NS_PER_TICK) / 1000;
	evtimer_add(&ctr->timer, &tv);
}
```

The reproduced libevent behavior confirms this is immediately due:

- `event_add` schedules `now + tv` in `lib/libevent/event.c:722`.
- `timeout_next` uses a zero wait for due timers in `lib/libevent/event.c:805`.
- `timeout_process` activates due timers again in `lib/libevent/event.c:830`.

Impact: the VM event thread loops through immediate PIT timer callbacks and IRQ assertion work without sleeping, consuming host CPU from attacker-controlled guest PIT I/O.

## Why This Is A Real Bug

The guest controls the PIT counter value through normal emulated port I/O. The code converts the guest-selected counter period to microseconds by truncating sub-microsecond values to zero. A zero `struct timeval` does not represent a minimal PIT delay in libevent; it schedules an immediately due timer. Because periodic PIT modes re-add the timer from the callback using the same zero interval, the host repeatedly wakes and executes callback work without delay. This is a direct guest-triggered host CPU denial of service.

## Fix Requirement

The timeout passed to `evtimer_add()` must never be zero for a nonzero PIT counter. The nanosecond-to-microsecond conversion must round up so any positive PIT interval becomes at least `1` microsecond.

## Patch Rationale

The patch changes both timeout calculations from truncating division to ceiling division:

```c
(start * NS_PER_TICK + 999) / 1000
```

This preserves the existing microsecond `struct timeval` representation while ensuring sub-microsecond positive PIT periods are represented as `1` microsecond instead of `0`. Applying the same rounding in both `i8253_reset()` and `i8253_fire()` prevents both the initial timer arm and periodic re-arm from becoming immediately due.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/vmd/i8253.c b/usr.sbin/vmd/i8253.c
index 00b0945..e9a29d3 100644
--- a/usr.sbin/vmd/i8253.c
+++ b/usr.sbin/vmd/i8253.c
@@ -348,7 +348,7 @@ i8253_reset(uint8_t chn)
 
 	i8253_channel[chn].in_use = 1;
 	i8253_channel[chn].state = 0;
-	tv.tv_usec = (i8253_channel[chn].start * NS_PER_TICK) / 1000;
+	tv.tv_usec = (i8253_channel[chn].start * NS_PER_TICK + 999) / 1000;
 	clock_gettime(CLOCK_MONOTONIC, &i8253_channel[chn].ts);
 	evtimer_add(&i8253_channel[chn].timer, &tv);
 }
@@ -374,7 +374,7 @@ i8253_fire(int fd, short type, void *arg)
 
 	if (ctr->mode != TIMER_INTTC) {
 		timerclear(&tv);
-		tv.tv_usec = (ctr->start * NS_PER_TICK) / 1000;
+		tv.tv_usec = (ctr->start * NS_PER_TICK + 999) / 1000;
 		evtimer_add(&ctr->timer, &tv);
 	} else
 		ctr->state = 1;
```